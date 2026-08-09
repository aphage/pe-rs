# dump 情况分析和处理

本文档描述 pe-rs 对"从内存 dump 出来的 PE 修复导入表"的处理流程:为什么找 IAT、各情形用哪条扫描线、如何把地址恢复成 (模块, 函数) 重建导入表。**代码反向映射**——每个分支标注实际实现入口(函数 + 文件)。

> 代码位置(2026-08 重构后,workspace 拆成两套 API):下述流程实现位于
> `crates/pe-scylla/src`(`api/iat_scanner.rs`、`api/iat_fixer.rs`、
> `feature/rebase.rs`、`process/mod.rs`),依赖 `crates/pe-edit` 的镜像模型
> `PeDocument` 与 `io::pe` 的 parse/serialize。文中 `api/…` 均指
> `crates/pe-scylla/src/api/…`。

## 0. 完整管线(代码)

```
dump(pid)                                        # process/mod.rs: 读进程内存 → PeDocument
  ├─ doc.imports = parse_imports_from_doc(…)     # 仅当 Import 目录有效、OFT 完整时才有意义
  │
  ├─ ProcessResolver::for_process(pid)[.with_fingerprints()]
  │                                              # 进程已加载模块导出表 → 地址解析器
  ├─ 按情形选扫描线: doc.scan(&resolver, ScanOptions{ method })
  │     Resolver      # 情形 A: 值经 resolver 校验, 按 NULL 分组取最长 run
  │     Reflection    # 情形 B/C: 纯结构, 输出原槽
  │     CodeReference # 情形 D: 反汇编代码节, 全量引用集
  │
  ├─ (可选) recover_dump_imports(&resolver)      # 直接把 dump 的导入表恢复成名字
  │
  ├─ fix_iat(&scan, &resolver, IatFixOptions)    # 解析 → 分组 → 重建导入目录
  │
  └─ serialize → save                            # writer 把重建的导入表落盘
```

关键点:找 IAT 的目的是**修复导入表再 dump**。压缩壳(UPX)加载后 `OriginalFirstThunk` 可能为 0 或等于 `FirstThunk`,结构仍可找到 IAT;保护壳(VMProtect)把 `DataDirectory[IAT]` 抹 0、清空导入表、且把 IAT 拆散——需要代码引用定位。

## 1. 相对正常的导入表(结构驱动)

### 1A. Import 目录有效

实现:`scan_by_reflection`(`api/iat_scanner.rs`)、`recover_dump_imports`(`api/iat_fixer.rs`)

```
for desc in import_descs, desc 等于 NULL 退出:
    if desc 判断是否有效:
        if OriginalFirstThunk == 0 and FirstThunk == 0:
            FirstThunk 被破坏 -> 停止遍历                 # 实现: 静默 break
        if OriginalFirstThunk == 0 or OriginalFirstThunk == FirstThunk:
            # OFT 已被作为 IAT 使用(loader 覆写), 需反射处理
            # 遍历 [FirstThunk, NULL] 收集原槽(地址)
            collect_thunk_array(doc, Rva(FirstThunk), psize, &mut entries)
        else:
            # OFT 有效 -> 常规按名解析
            parse_thunks(doc, Rva(OriginalFirstThunk), psize)   # hint/name
    else:
        停止遍历
```

- 只对 **OFT 被覆写** 的描述符反射其 `FirstThunk`(OFT 完整者跳过——名字本就可解析)。
- `ScanMethod::Reflection` 输出原槽 `IatScan`,交给 `fix_iat` 解析重建。
- `recover_dump_imports(resolver)` 把反射槽经 resolver 解析成 `(module, function)`,与 OFT 完整者的 hint/name 合并,恢复**完整**导入表;解析不了的槽进 `DumpImportRecovery::unresolved`。

> 注意:`parse_imports_from_doc` 是**文件级**语义(OFT==0 时回退用 FT 当名字 RVA 解析),对磁盘文件正确;但对**已加载 dump**(FT 存的是地址)会解析出垃圾/空——这正是 `recover_dump_imports` 存在的原因。

### 1B. Import 目录无效,但 `DataDirectory[IAT]` 有效

实现:`collect_iat_dir_entries`(`api/iat_scanner.rs`,由 `scan_by_reflection` / `recover_dump_imports` 调用)

```
iat_array = DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] 指向的数组
for iat = iat_array.begin; iat 在目录 size 内 and *iat != NULL;:
    for ; iat 在 size 内 and *iat != NULL; iat++:    # 收集当前子数组
        entries.push(*iat)                            # 反射: 加入列表后续统一处理
    iat++                                             # 跳过 NULL, 进入下一个子数组
```

- 单 NULL 分模块,**双 NULL 收尾**(见 §6 布局),目录 `size` 为界。
- 与 1A 一致:`ScanMethod::Reflection` 输出原槽,`recover_dump_imports` 解析成名字。

### 1C. 两者都无效

```
记录错误, 接下来只能对代码进行扫描处理
ScanMethod::CodeReference     # §3
```

## 2. 根据 IAT 重建导入表(地址 → (模块, 函数))

实现:`ProcessResolver::for_process(pid)[.with_fingerprints()]`(`process/mod.rs`)

- 遍历进程已加载模块(`EnumProcessModules`)读各模块导出表 → `offset-in-module → 函数` 映射(`read_module_exports`),这是"dll 级别 [函数地址数组] 的地址"。
- 对每个 IAT 地址:
  1. **落在某已加载模块范围内** → `(address - base)` 查导出表偏移 → `(module, function)`。
  2. **不在任何已知模块**(可能是手动映射的内存加载模块):
     - 读该地址的代码字节,与系统加载副本的导出**代码指纹**比对(`resolve_fingerprint`:前 8 字节索引 + 16 字节验证)。
     - 内存模块代码与系统副本逐字节一致,即使 PE 头被擦也能识别;代价是要求系统里有**同一 DLL 的已加载副本**。文档原设计是"对原模块导出表遍历匹配 / 读内存模块自己的导出表"——pe-scylla 用代码指纹取代,对擦头场景更稳,但"只有内存模块无原模块"的自定义 DLL 识别不了(落到 unresolved)。

## 3. 扫描代码搜索 IAT(代码引用)

实现:`scan_by_code_reference`(`api/iat_scanner.rs`,iced-x86)

- 反汇编每个可执行节,只收 Scylla `isIatReferenceOpcodes` 指令族:`call/jmp/push`(FF)、`mov`(8B/89/A0-A3/C6/C7)、`lea`(8D)。
- 收集直接内存寻址的目标:x64 RIP-relative / x86 绝对寻址。
- 过滤:目标必须**指针对齐** + 落在**非代码节**(数据段);可选 `validate_slots` 用 resolver 校验槽内容。
- 输出按 RVA 排序去重的**全量引用集**(可跨普通 IAT + delay-load IAT 等多段),供 `IatTable` 筛选。

## 4. 三条扫描线选型

| 情形 | 结构状态 | 扫描方式 | 入口 |
|---|---|---|---|
| A | Import 目录有效、OFT 完整 | Resolver / 直接解析 | `parse_imports_from_doc` |
| B | 加载后 OFT 被覆写(压缩壳) | **Reflection**(1A) | `scan_by_reflection` / `recover_dump_imports` |
| C | Import 目录清空、仅 IAT 目录在 | **Reflection**(1B) | `scan_by_reflection`(子数组) |
| D | 结构全抹 + IAT 拆散(保护壳) | **CodeReference** | `scan_by_code_reference` |

- `ScanMethod::Resolver`(`scan_by_resolver`):值经 resolver 校验,按 NULL 分隔符分组(`max_null_gap`),取最长连续 run。
- `ScanMethod::CodeReference`:反汇编全量引用集。
- `ScanMethod::Reflection`:纯结构(1A/1B),输出原槽交给 `fix_iat`。

## 5. 重建与落盘

- `fix_iat`(`api/iat_fixer.rs`):逐槽 `resolver.resolve` → `group_resolved` 分组成描述符 → `rebuild_import_table`(写入 descriptors + INT/IAT + 名字串,并把 rich `doc.imports` 写回)→ 可选 `redirect_iat` 覆写原 IAT 槽。
- `IatTable` / `fix_iat_table`:手工把 CodeReference 全量集 + `add_region` 拼成正常导入表(处理拆散 IAT)。
- `serialize`(`io/pe/writer.rs`):rich imports 为空则清零 Import/IAT 目录;有 imports 且现有目录不匹配则追加 `.peimp` 节重建。所以 dump→fix→save 后落盘的是干净的、按名的新导入表。

## 6. DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] 指向的布局结构

`IMAGE_DIRECTORY_ENTRY_IAT` 指向的是一整块连续内存,它由多个子数组串联组成,每个子数组对应一个被导入的 DLL(`collect_iat_dir_entries` 正是按此布局行走):
```text
起始地址 (VirtualAddress)
+---------------------------+
| [DLL A 的第1个函数地址]    |  <- IMAGE_THUNK_DATA
| [DLL A 的第2个函数地址]    |
| [DLL A 的第3个函数地址]    |
| 0x00000000 (NULL)         |  <- 子数组结束符 (End of DLL A)
+---------------------------+
| [DLL B 的第1个函数地址]    |
| [DLL B 的第2个函数地址]    |
| 0x00000000 (NULL)         |  <- 子数组结束符 (End of DLL B)
+---------------------------+
| 0x00000000 (NULL)         |  <- 【你所说的结束标志】空块（无更多DLL）
+---------------------------+
| (后续内存，直到 Size 边界) |
+---------------------------+
```
