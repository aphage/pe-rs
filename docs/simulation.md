# 模拟测试程序(dump → 修复 → 再运行)

`crates/sim-target` 是一个**真实进程**层面的端到端模拟:Scylla 式的工作流
"对运行中的、被破坏/隐藏过的 PE 做 dump → 扫描 → 修复导入表 → 落盘 → 再运行"。
它由一个**自毁目标程序**(`sim-target` bin)和一个**harness**(`dump_sim`
example / 忽略的集成测试)组成,对应 `dump 情况分析和处理.md` 的四种情形。

## 场景与扫描线选型

| 场景 | 目标程序对自身内存做的破坏 | harness 用的扫描线 | 修复后产物可运行 |
|---|---|---|---|
| `normal` (A) | 无(一个普通运行进程) | `CodeReference`(值校验) | ✓ |
| `oft` (B) | 每个导入描述符的 `OriginalFirstThunk` 置 0 | `Reflection` | ✓ |
| `iatdir` (C) | Import 数据目录抹 0,保留 IAT 目录 | `Reflection` | ✓ |
| `erased` (D) | Import+IAT 目录都抹 0,并把 IAT 按模块**拆散**到非连续 scratch、改写自身代码引用 | `CodeReference`(值校验) | ✓ |

> 注:A 用 `CodeReference` 而非文档表的 `Resolver`,因为对运行中的 dump,
> Resolver 的指针 run 扫描会把 `.rdata` 里大量可解析指针并入,产生非连续分组;
> 代码引用扫描恰好只命中 per-module 的 IAT 槽。D 的分散槽仍持有**可解析的**加载
> 地址(与真实保护壳不同),所以 `validate_slots` 保持开启以滤掉无关的代码引用。

## 为什么目标程序是 `no_std`

让 dump 产物可运行的真正难点不是导入表,而是**运行时状态**。`std`/CRT 程序启动时
会把绝对函数指针(经 `GetProcAddress` 解析的地址)懒写入 `.data`;这些槽在链接时
在 `.reloc` 里,loader 重定位时会把它们当"镜像内指针"再加一次增量 → dump 再运行
时跳到非法地址崩溃。`sim-target` 用 `no_std`(无 CRT、无堆、无懒初始化全局)保持
`.data` 干净,如同刚解压的壳程序。运行时只有编译器强加的少量辅助符号
(`memcpy`/`__chkstk`/`__CxxFrameHandler3`/`_fltused`),由 `main.rs` 自己提供。

## 修复产物如何做到可运行

为了"修复后 dump 独立运行",pe-rs 侧做了三处配套改动:

1. **就地重建 IAT**(`fix_iat` + `IatFixOptions::reuse_iat_slots`,默认开):
   当每个模块的槽连续时,重建的描述符 `FirstThunk` 直接指回**原 IAT 槽 RVA**,
   loader 把名字解析出的地址写进代码真正引用的那些槽(`call [rip+disp]` 落点)。
   含槽的节标记 `IMAGE_SCN_MEM_WRITE`。若槽不连续,回退为把代码引用改写去新表。
2. **代码引用改写**(`PeDocument::remap_iat_references`):把可执行节里所有指向
   旧 IAT 槽的 direct-memory 操作数(`call/jmp/mov/lea [rip+disp]`)的位移改写为
   新表槽位。就地模式无法成立(槽分散/交错)时,用它在重建后把代码指到新 IAT。
3. **writer 保留 bss/raw 边界**:dump 是按 `virtual_size` 读节的,未初始化的
   `.bss` 尾巴里是运行时的陈旧堆/分配器状态;`serialize` 只写 `size_of_raw_data`
   那么长,让 loader 零填充尾巴,而不是把陈旧字节拷进修复产物。

## 使用

```text
# 构建目标程序 + harness
cargo build -p sim-target

# 跑单个场景:spawn 目标 → 破坏 → dump → 扫描 → 修复 → 保存 → 再运行验证
cargo run -p sim-target --example dump_sim -- --scenario erased --out fixed.exe

# 四场景端到端(忽略测试;会 spawn 真实进程)
cargo test -p sim-target -- --ignored
```

### 目标程序的两种模式

- 默认 / `verify`:正常跑,打印 `SIM_TARGET_OK`,退出 0 —— 修复产物就是这样被拉起验证的。
- `corrupt <scenario>`:按场景破坏自身内存后打印 `SIM_TARGET_READY:<pid>`,然后
  sleep 直到 harness 来 dump(harness dump 完会杀掉它)。

`erased`(D)的拆散:每个模块的 FirstThunk 数组被拷进一个 `.data` 里的静态 scratch
缓冲区,块与块之间留隙(非连续);然后目标程序用 opcode 模式扫描自己的 `.text`,
把指向旧槽的 RIP-relative 引用位移改写指向 scratch 新槽。若改写不到任何引用,降级
为"仅抹目录"(仍是有效的 D:结构全抹、靠代码引用定位 IAT)。

## 局限

- 只针对 x64 宿主(`x86_64-pc-windows-msvc`);x86 绝对寻址的 `.reloc` 处理留作后续。
- `sim-target` 的 bin 是 `no_std`,不能作为 `cargo test` 的测试目标构建
  (`[[bin]] test = false`),其端到端验证是 `#[ignore]` 的集成测试。
- 整个 workspace 设了 `panic = "abort"`(sim-target 无 unwinder);其余 crate 的
  测试失败因此以进程中止而非逐测 panic 呈现。
