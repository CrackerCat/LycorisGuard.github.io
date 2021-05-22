---
layout: post
title: Windows内核对象之进程、文件、注册表对象的ObjectHook的学习
date: 2016-03-23 20:18:12 +0900
category: windowsDriver
---
## 0x01 OBJECT_HEADER结构
　　![ObjectHeader](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/1.png)

　　这是对象的数据结构的形态，其中OBJECT_HEADER的结构如下
```cpp
typedef struct _OBJECT_HEADER
{
    LONBG PointerCount;
    union
    {
        LONG HandleCount;
        volatile PVOID NextToFree;
    }
    POBJECT_TYPE Type;
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;
    union
    {
        POBJECT_CREATE_INFORMNATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    }
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
}OBJECT_HEADER,*POBJECT_HEADER;
```
　　对象头中保存着Body的地址，所以可以用下面的宏得到对象头

```cpp
#define OBJECT_TO_OBJECT_HEADER(o)\
     CONTAINING_RECORD((o),OBJECT_HEADER,Body)
#define CONTAINING_RECORD(address,type,field)\
     ((type*)(((ULONG_PTR)Address)-(ULONG_PTR)(&(((type*)0)->field))))
```

　　实际硬偏移就是Body - 0x18 = Header  (XP下)
## 0x02 OBJECT_TYPE
　　在I/O子系统初始化的时候，系统就创建了Adapter，Controller，Device，Driver，IoCompletion，File等对象类型。

　　其中创建文件对象类型的部分如下所示
```cpp
IoInitSystem()-->IopCreateObjectTypes()
    ...
    RtlInitUnicodeString( &nameString, L"File" );
    objectTypeInitializer.DefaultPagedPoolCharge = IO_FILE_OBJECT_PAGED_POOL_CHARGE;
    objectTypeInitializer.DefaultNonPagedPoolCharge = IO_FILE_OBJECT_NON_PAGED_POOL_CHARGE +
                                                      sizeof( FILE_OBJECT );
    objectTypeInitializer.InvalidAttributes = OBJ_PERMANENT | OBJ_EXCLUSIVE | OBJ_OPENLINK;
    objectTypeInitializer.GenericMapping = IopFileMapping;
    objectTypeInitializer.ValidAccessMask = FILE_ALL_ACCESS;
    objectTypeInitializer.MaintainHandleCount = TRUE;
    objectTypeInitializer.CloseProcedure = IopCloseFile;
    objectTypeInitializer.DeleteProcedure = IopDeleteFile;
    objectTypeInitializer.ParseProcedure = IopParseFile;
    objectTypeInitializer.SecurityProcedure = IopGetSetSecurityObject;
    objectTypeInitializer.QueryNameProcedure = IopQueryName;
    objectTypeInitializer.UseDefaultObject = FALSE;

    PERFINFO_MUNG_FILE_OBJECT_TYPE_INITIALIZER(objectTypeInitializer);

    if (!NT_SUCCESS( ObCreateObjectType( &nameString,   // 对象类型名称
                                      &objectTypeInitializer,//重要结构
                                      (PSECURITY_DESCRIPTOR) NULL,//保留
                                      &IoFileObjectType ))) { //对象类型
        return FALSE;
    }
```
　　这里就要说说OBJECT_TYPE的结构了：
```cpp
typedef struct _OBJECT_TYPE {
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;            // Copy from object header for convenience
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONG Key;
    ERESOURCE ObjectLocks[4];
} OBJECT_TYPE, *POBJECT_TYPE;
```
　　OBJECT_TYPE_INITIALIZER就是在IopCreateOBjectTypes()中初始化的那个结构
```cpp
typedef struct _OBJECT_TYPE_INITIALIZER {
    USHORT Length;
    BOOLEAN UseDefaultObject;
    BOOLEAN CaseInsensitive;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    PVOID OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    PVOID ParseProcedure;                    //一般对象钩子 Hook 的函数
    PVOID SecurityProcedure;
    PVOID QueryNameProcedure;
    PVOID OkayToCloseProcedure;              //sudami要hook的函数
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;
```
　　在这个重要的结构中就有我们Object Hook的目标函数了。在很多操作对象的函数中调用了很多的这些函数，这里我们可以Hook这个点，来达到保护的目的。

 

　　在系统中有很多的对象，文件对象，注册表对象，进程对象，线程对象等等，每个对象在全局都有一个OBJECT_TYPE结构，而且所有对象类型一样的对象的OBJECT_TYPE都是一样的。

　　这是进程对象的，其名称是Process，类型为IoProcessObjectType
![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/2.png)

　　下面是文件对象的对象类型，类型名为File，对象类型为IoFileObjectType，一般进程的绝对路径都是遍历其句柄表，获得文件对象，然后根据IoQueryFileDosDeviceName函数获得绝对地址，这里深入讨论这个。

![2](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/3.png)

　　总结上面的就是OBJECT_HEADER 中有两个重要结构一个是OBJECT_TYPE，一个是Body

　　我们可以根据Body->OBJECT_HEADER->OBJECT_TYPE->TypeInfo 就可以替换里面的函数达到ObjectHook了
## 0x03 ObjectHook
　　我们看一下一般常见的ObjectHook，下面是进程对象的Object Hook
```cpp
VOID HookProcessObjectType()
{
    ULONG pid;
    pid = 1508; //这里为要传入保护的进程ID

    PsLookupProcessByProcessId(pid,&eProcess);//得到进程对象
    _asm{
        push eax
            mov eax,eProcess
            mov eax,[eax-0x10]//这里eProcess-0x18 得到ObjectHeader
　　　　　　　　　　　　　　　　　　//ObjectHeader+0x8 得到OBJECT_TYPE
            mov pEprocesstType,eax//得到ObjectType
            pop eax
    }
    OldParseProcess = pEprocesstType->TypeInfo.ParseProcedure;
    if (!MmIsAddressValid(OldParseProcess))
    {
        return ;
    }
    pEprocesstType->TypeInfo.ParseProcedure = fakeParseProcess; //替换其中的ParseProcedure
    return ;

}
//我们的fake函数
NTSTATUS fakeParseProcess(PVOID Object)
{
    PEPROCESS kProcess;
    NTSTATUS status;
    kProcess = (PEPROCESS)Object;
    //和我们要保护的进程名称比较，如果要操作的进程为要保护的进程
    //则直接返回
    if (strstr((char*)((PUCHAR)kProcess+0x174),(char*)((PUCHAR)eProcess +0x174))==0)
    {
        return 0;
    }
    //调用原来的函数
    _asm
    {
            push eax
            push Object
            call OldParseProcess
            mov status,eax
            pop eax
    }
    return status;

}
```
　　下面是注册表对象的Object Hook
```cpp
VOID HookRegObjectType()
{
    HANDLE RegKeyHandle ;
    OBJECT_ATTRIBUTES oba;
    UNICODE_STRING RegPath;
    NTSTATUS status;
    PVOID KeyObject;

    RegKeyHandle = 0;

    RtlInitUnicodeString(&RegPath,L"\\Registry\\Machine\\System");

    InitializeObjectAttributes(&oba,&RegPath,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,0,0);

    status = ZwOpenKey(&RegKeyHandle,KEY_QUERY_VALUE,&oba);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwOpenKey Error!\n");
        return ;
    }
       //通过键值句柄得到对象
    status = ObReferenceObjectByHandle(RegKeyHandle,GENERIC_READ,
        NULL,
        KernelMode,
        &KeyObject,
        0
        );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObReferenceObjectByHandle Error!\n");
        ObDereferenceObject(KeyObject);
        NtClose(RegKeyHandle);
        return ;
    }

        //和上面一样获得对象类型
    __asm
    {
        push eax
            mov eax,KeyObject
            mov eax,[eax-0x10]
            mov CmpKeyObjectType,eax
            pop eax
    }    
        //保存原始的函数
    OldParseKey = CmpKeyObjectType->TypeInfo.ParseProcedure;

    if (!MmIsAddressValid(OldParseKey))
    {
        ObDereferenceObject(KeyObject);
        ZwClose(RegKeyHandle);
        return ;
    }
    //替换成我们的函数
    CmpKeyObjectType->TypeInfo.ParseProcedure = (ULONG)FakeParseKey;

    ObDereferenceObject(KeyObject);
    ZwClose(RegKeyHandle);
    return ;

}
//fake函数
NTSTATUS FakeParseKey(POBJECT_DIRECTORY RootDirectory,
    POBJECT_TYPE ObjectType,
    PACCESS_STATE AccessState,
    KPROCESSOR_MODE AccessCheckMode,
    ULONG Attributes,
    PUNICODE_STRING ObjectName,
    PUNICODE_STRING RemainingName,
    PVOID ParseContext ,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos ,
    PVOID *Object)
{
    NTSTATUS stat ;
    WCHAR Name[300];
    RtlCopyMemory(Name , ObjectName->Buffer , ObjectName->MaximumLength );
    _wcsupr(Name);
    if (wcsstr(Name , L"RUN"))
    {
        //检查是不是要保护的注册表键
        return STATUS_OBJECT_NAME_NOT_FOUND ;
    }
    DbgPrint("Key");   //这里我打印一句话
         //在调试的过程中，基本上没走一个函数都会打印很多次，说明注册表对象的操作特别频繁
    //调用原来的函数
    __asm
    {
        push eax
            push Object
            push SecurityQos
            push ParseContext
            push RemainingName
            push ObjectName
            push Attributes
            movzx eax, AccessCheckMode
            push eax
            push AccessState
            push ObjectType
            push RootDirectory
            call OldParseKey
            mov stat, eax
            pop eax
    } 
    return stat ;
}
```
　　下面是文件对象的Object Hook
```cpp
VOID HookFileObjectType()
{
    OBJECT_ATTRIBUTES oba;
    NTSTATUS status;
    UNICODE_STRING filePath;
    HANDLE hFile;
    IO_STATUS_BLOCK iostatus;
    PVOID FileObject;

    RtlInitUnicodeString(&filePath,L"\\??\\C:");

    InitializeObjectAttributes(&oba,&filePath,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,0,0);

    ZwOpenFile(&hFile,GENERIC_ALL,&oba,&iostatus,FILE_SHARE_READ | FILE_SHARE_WRITE,FILE_SYNCHRONOUS_IO_NONALERT);

    status = ObReferenceObjectByHandle(hFile,GENERIC_READ,NULL,KernelMode,&FileObject,0);

    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(FileObject);
        ZwClose(hFile);
        return; 
    }

    __asm{
        push eax;
        mov eax,FileObject
        mov eax,[eax - 0x10]
        mov pFileType,eax
        pop eax
    }

    OldParseFile = pFileType->TypeInfo.ParseProcedure;
    if (!MmIsAddressValid(OldParseFile))
    {
        ObDereferenceObject(FileObject);
        ZwClose(hFile);
        return ;
    }

    pFileType->TypeInfo.ParseProcedure = (ULONG)fakeFileParseProcedure;

    ObDereferenceObject(FileObject);

    ZwClose(hFile);
    return;
}

NTSTATUS fakeFileParseProcedure(    IN PVOID ParseObject,
    IN PVOID ObjectType,
    IN PACCESS_STATE AccessState,
    IN KPROCESSOR_MODE AccessMode,
    IN ULONG Attributes,
    IN OUT PUNICODE_STRING CompleteName,
    IN OUT PUNICODE_STRING RemainingName,
    IN OUT PVOID Context OPTIONAL,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
    OUT PVOID *Object)
{
    NTSTATUS ntStatus ;
    PVOID NamePool;
    ntStatus = STATUS_SUCCESS;
    if (RemainingName->Buffer)
    {
        NamePool = ExAllocatePool(NonPagedPool,RemainingName->Length + 2);
        if (NamePool)
        {
            RtlCopyMemory(NamePool,RemainingName->Buffer,
                RemainingName->Length + 2);
            _wcsupr((wchar_t*)NamePool);
            if (wcsstr((wchar_t*)NamePool,L"TEST.TXT"))
            {
                ExFreePool(NamePool);
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    __asm{
            push eax
            push Object
            push SecurityQos
            push Context 
            push RemainingName
            push CompleteName
            push Attributes
            push AccessMode
            push AccessState
            push ObjectType
            push ParseObject
            call OldParseFile
            mov ntStatus,eax
            pop eax
    }
    return ntStatus;
}
```
　　自己Hook的要还原就是将保存的原始函数地址 替换回去就行了。

　　至于对于别人的Object Hook的检测与恢复我目前想到的就是通过IopCreateObjectTypes（）函数在赋值的时候，将其赋值的函数地址获得，经过比较看是否被替换了。至于刚开始没有赋值的函数，我们可以通过调试的时候找出函数原型，然后获得地址比较。这部分我还没时间做。

## 0x04 参考sudami大牛对NtClose函数中对ObjectHook的探索
　　下面是sudami大牛对于NtClose()函数中对Object Hook的探索过程。

　　首先用IDA分析NtClose函数
![3](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/4.png)
　　这里直接进入ObpCloseHandle函数
![4](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/5.png)
　　这里就判断是否是内核句柄，内核句柄就是系统进程创建的对象的句柄，应该去除句柄的KERNEL_HANDLE_FLAG标志，然后Attach到System进程，在其句柄表中查找
![5](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/6.png)
![6](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/7.png)
　　附着到system进程，然后返回ObpCloseHandle函数
![7](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/8.png)
　　下面就是通过ExMapHandleToPointer函数获得系统句柄表，
　　在通过ObpCloseHandleEntry函数关闭句柄
![8](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/9.png)
　　我们进入ObpCloseHandleEntry函数首先根据您对象体，获得对象头，然后偏移8的地方是对象类型
　　对象体的低三位要去掉，才是真正的对象体，减去偏移就是对象头
![9](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/10.png)
　　这里判断了对象类型结构体里面的OkayToCloseProcedure函数是否存在
![10](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/11.png)
　　 这里就调用OkayCloseProcedure函数
![11](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/12.png)
 　　我们hook了OkayCloseProcedure函数就可以让其直接走到 loc_51D1F6 的地方
![12](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-03-23/13.png)
　　这里就是对于NtClose中Object Hook的思路。

　　我们的函数原型是
```cpp
 typedef NTSTATUS
         (NTAPI *OB_OKAYTOCLOSE_METHOD)(
               IN PEPROCESS Process OPTIONAL,
               IN PVOID Object,
               IN HANDLE Handle,
               IN KPROCESSOR_MODE AccessMode

　　　　　);
```
　　下面是安装Hook过程
```cpp
void InstallHook()
{
    NTSTATUS status;
    PVOID CureentProcess;

    CureentProcess = (PVOID)PsGetCurrentProcess();
    __asm
    {
        push eax
        mov eax,CureentProcess
        mov eax,[eax-0x10]
        mov EprocessObjectType,eax
        pop eax
    }


    DbgPrint("Eprocess Object Type :%08x \n" , EprocessObjectType );

    Old_OkayToCloseProcedure = EprocessObjectType->TypeInfo.OkayToCloseProcedure;

    DbgPrint("Eprocess OkayToCloseProcedure routine :%08x \n ", Old_OkayToCloseProcedure );
    DbgPrint("DeleteProcedure routine :%08x \n ", 
                EprocessObjectType->TypeInfo.DeleteProcedure);

    if (!MmIsAddressValid(Old_OkayToCloseProcedure)) {
        DbgPrint("!MmIsAddressValid");
        return ;
    }

    EprocessObjectType->TypeInfo.OkayToCloseProcedure = fake_OkayToCloseProcedure;
    g_bObjectHook = TRUE;

    return ;
}


NTSTATUS
fake_OkayToCloseProcedure(    
    PEPROCESS Process OPTIONAL,
    PVOID Object,
    HANDLE Handle,
    KPROCESSOR_MODE AccessCheckMode
    )
{
    NTSTATUS stat ;
    PVOID ProcessObject;
    

    stat = ObReferenceObjectByHandle(Handle,
        GENERIC_READ,
        NULL,
        KernelMode,
        &ProcessObject,
        0);

    if (!NT_SUCCESS( stat )) {
        dbg("ObReferenceObjectByHandle failed!\n");
        goto _orig_;
    }

    // 若操作的对象是我们关心的进程，且是其他进程在操作
    // 拒绝之
    if ( (DWORD)g_target_eprocess == (DWORD)ProcessObject &&
        (DWORD)g_target_eprocess != (DWORD)Process ) {

        DbgPrint("%d :denny it \n", (DWORD)Process);
        return 0 ;
    }

_orig_:
    __asm
    {
        push eax
        movzx eax, AccessCheckMode
        push eax
        push Handle
        push Object
        push Process
        call Old_OkayToCloseProcedure

        mov stat, eax
        pop eax
    } 

    return stat ;
} 
```