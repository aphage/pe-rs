# dump 情况分析和处理


## 相对正常的导入表
```
if IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] 是否有效 {
    import_descs = 获取指向[IMAGE_IMPORT_DESCRIPTOR,NULL]数组
    for desc in import_descs,desc等于NULL退出 {
        if desc 判断是否有效 {
            if IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk == 0 and IMAGE_IMPORT_DESCRIPTOR.FirstThunk == 0 {
                FirstThunk 被破坏，记录错误，退出循环
            }
            if IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk == 0 or IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk等于FirstThunk {
                说明OriginalFirstThunk已经被作为IAT使用了，需要对IAT 进行反射处理，遍历[IMAGE_THUNK_DATA,NULL]加入列表后续统一进行反射处理
            } else {
                说明OriginalFirstThunk有效，遍历[IMAGE_THUNK_DATA,NULL]导入的函数即可
            }
        } else {
            记录错误，退出循环
        }
    }
} else {
    if IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] 是否有效 {
        iat_array = 获取指向[IMAGE_THUNK_DATA(Function),IMAGE_THUNK_DATA(Function),NULL,IMAGE_THUNK_DATA(Function),NULL,NULL]数组

        for iat = iat_array.begin;iat 地址不能超过IMAGE_DIRECTORY_ENTRY_IAT.大小 and iat != NULL; iat++ {
            
            for ;iat 地址不能超过IMAGE_DIRECTORY_ENTRY_IAT.大小 and iat != NULL; iat++ {
                需要对IAT 进行反射处理，加入列表后续统一进行反射处理
            }
            
            iat++//跳过NULL，进入下一个IAT数组
        }
    
    } else {
        记录错误，接下来只能对代码进行扫描处理了
    }
}
```

## 根据IAT重建导入表

可以先遍历目标进程的模块列表

dll级别[函数地址数组[地址]]

遍历地址，使用内存查询函数，查询地址的基地址，如果是模块基地址就是模块地址，也是模块句柄，再根据进程的模块列表比对，如果匹配上的话就可以通过模块的导出表匹配地址偏移确定导出函数

如果函数地址的基地址不是模块地址，可以判断是否是内存加载模块，如果同时存在原模块和内存模块，则对原模块的导出表进行遍历匹配，如果只有内存模块没有元模块时，查看内存模块PE结构的导出表是否存在，存在就对导出表进行遍历匹配，否则就标记为异常地址

## 扫描代码搜索IAT

把搜索到的地址进行判断，地址否是是可执行的，非可执行的就是数据段，可执行的话，加入IAT列表，后面可以根据IAT重建导入表


## DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]指向的布局结构

IMAGE_DIRECTORY_ENTRY_IAT 指向的是一整块连续内存，它由多个子数组串联组成，每个子数组对应一个被导入的 DLL：
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