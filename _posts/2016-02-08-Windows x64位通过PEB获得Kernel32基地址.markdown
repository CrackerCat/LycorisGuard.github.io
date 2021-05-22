---
layout: post
title: Windows x64位通过PEB获得Kernel32基地址
date: 2016-02-08 17:59:12 +0900
category: windowsDebug
---

在64位系统下

gs:[0x30] 指向TEB

gs:[0x60] 指向PEB

```cpp
kd> dt _TEB
nt!_TEB
   +0x000 NtTib            : _NT_TIB
        +0x000 ExceptionList   : Ptr64 _EXCEPTION_REGISTRATION_RECORD
   +0x008 StackBase        : Ptr64 Void
   +0x010 StackLimit       : Ptr64 Void
   +0x018 SubSystemTib     : Ptr64 Void
   +0x020 FiberData        : Ptr64 Void
   +0x020 Version          : Uint4B
   +0x028 ArbitraryUserPointer : Ptr64 Void
   +0x030 Self             : Ptr64 _NT_TIB
   +0x038 EnvironmentPointer : Ptr64 Void
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : Ptr64 Void
   +0x058 ThreadLocalStoragePointer : Ptr64 Void
   +0x060 ProcessEnvironmentBlock : Ptr64 _PEB   //此处保存着PEB地址
```
这里用内联汇编获得PEB基地址

```cpp
.CODE
  GetPeb PROC
    mov rax,gs:[60h]
  ret
  GetPeb ENDP
 END
```

声明之后即可调用该函数获得PEB地址，关于内联汇编的使用请自行百度
```cpp
extern "C" PVOID64 _cdecl GetPeb();
```

下面在看PEB结构
```cpp
kd> dt _PEB
nt!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsLegacyProcess  : Pos 2, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 4, 1 Bit
   +0x003 SpareBits        : Pos 5, 3 Bits
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA    //此处是LDR链的地址
```

```cpp
kd> dt _PEB_LDR_DATA
nt!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr64 Void
   +0x010 InLoadOrderModuleList : _LIST_ENTRY
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY
```

InLoadOrderModuleList            模块加载顺序
InMemoryOrderModuleList          模块在内存中的顺序
InInitializationOrderModuleList  模块初始化装载顺序
```cpp
kd> dt _LDR_DATA_TABLE_ENTRY
nt!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
```

将结构都列举出来了之后，下面就是通过PEB和看到的偏移获取到模块基地址。
```cpp
#include<windows.h>
extern "C" PVOID64 _cdecl GetPeb();

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
}UNICODE_STRING, *PUNICODE_STRING;
int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
    PVOID64 Peb = GetPeb();
    PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb+0x018);  //0x018是LDR相对于PEB偏移   存放着LDR的基地址
    UNICODE_STRING* FullName; 
    HMODULE hKernel32 = NULL;
    LIST_ENTRY* pNode = NULL;
    pNode =(LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr+0x30));  //偏移到InInitializationOrderModuleList
    while(true)
    {
        FullName = (UNICODE_STRING*)((BYTE*)pNode+0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
        if(*(FullName->Buffer+12)=='\0')
        {
            hKernel32 = (HMODULE)(*((ULONG64*)((BYTE*)pNode+0x10)));//DllBase
            break;
        }
        pNode = pNode->Flink;
    }
    printf("%p",hKernel32);
    return 0;
}
```

第一个是Ntdll，第二个是KERNELBASE，第三个就是Kernel32