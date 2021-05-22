---
layout: post
title: ZwQueryVirtualMemory暴力枚举进程模块
date: 2016-03-22 17:31:12 +0900
category: windowsDriver
---
## 0x01 前言
　　常用的枚举模块的方法是在PEB中的三条链来枚举模块。

　　这里记录另一种通过ZwQueryVirtualMemory暴力枚举模块的方法。

## 0x02 使用ZwQueryVirtualMemory暴力枚举模块
```cpp
NTSTATUS
 NtQueryVirtualMemory(HANDLE ProcessHandle,       //目标进程句柄
　　　PVOID BaseAddress,                           //查询的基址
     MEMORY_INFORMATION_CLASS MemoryInformationClass, //枚举宏
     PVOID MemoryInformation,                     //接收信息的结构体
     SIZE_T MemoryInformationLength,              //缓冲区大小
     PSIZE_T ReturnLength);                       //返回实际长度

//枚举宏
typedef enum _MEMORY_INFORMATION_CLASS {  
            MemoryBasicInformation,  
            MemoryWorkingSetList,  
            MemorySectionName,  
            MemoryBasicVlmInformation  
} MEMORY_INFORMATION_CLASS;  
```
　　R0通过遍历SSDT获得函数地址。

　　我们要枚举进程模块信息, 需要用到两类内存信息MemoryBasicInformation和MemorySectionName,

　　MemoryBasicInformation的缓冲结构体

```cpp
 typedef struct _MEMORY_BASIC_INFORMATION {  
    PVOID       BaseAddress;           //查询内存块所占的第一个页面基地址
    PVOID       AllocationBase;        //内存块所占的第一块区域基地址，小于等于BaseAddress，
    DWORD       AllocationProtect;     //区域被初次保留时赋予的保护属性
    SIZE_T      RegionSize;            //从BaseAddress开始，具有相同属性的页面的大小，
    DWORD       State;                 //页面的状态，有三种可能值MEM_COMMIT、MEM_FREE和MEM_RESERVE
    DWORD       Protect;               //页面的属性，其可能的取值与AllocationProtect相同
    DWORD       Type;                  //该内存块的类型，有三种可能值：MEM_IMAGE、MEM_MAPPED和MEM_PRIVATE
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
```

　　MemorySectionName的缓冲结构体为
```cpp
//MemorySectionName 
typedef struct _MEMORY_SECTION_NAME  {  
    UNICODE_STRING Name;  
    WCHAR     Buffer[260];  
}MEMORY_SECTION_NAME,*PMEMORY_SECTION_NAME;
```
　　前者返回内存的基本信息, 比如: 内存区的基址,大小以及页面的各种属性等等, 而后者则返回内存段的名字,  也就是我们所要找的模块名.
　　利用前者我们可以过滤出类型为MEM_IMAGE的内存段并得到内存段的基址和属性, 利用后者我们可以得到模块名.

　　代码如下：
```cpp
VOID ListModuleThread(PVOID Context)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    ULONG StepAddress;
    ULONG Step2Address;
    ULONG BufferSize = 0x200;
    ULONG ReturnLength = 0;
    WCHAR LastImageName[260] = { 0 };
    HANDLE HandleProcess;
    PMEMORY_SECTION_NAME SectionName = NULL;
    MEMORY_BASIC_INFORMATION BasicInformation;
    PTHREAD_CONTEXT ThreadContext = Context;
    PMODULE_INFO FoundModule = NULL;
    pFnZwQueryVirtualMemory ZwQueryVirtualMemory = NULL;
    
    ZwQueryVirtualMemory = (pFnZwQueryVirtualMemory)
        KeServiceDescriptorTable.ServiceTableBase[ServiceId_NtQueryVirtualMemory];

    ntStatus = ObOpenObjectByPointer(ThreadContext->Process, OBJ_INHERIT, 
                                     NULL, 0, *PsProcessType, 
                                     ExGetPreviousMode(), &HandleProcess);
    if (!NT_SUCCESS(ntStatus)) {
        ExFreePoolWithTag(g_ModuleListHead, MEM_TAG);
        g_ModuleListHead = NULL;  goto _End;
    }

    SectionName = ExAllocatePoolWithTag(PagedPool, BufferSize, MEM_TAG);

    for (StepAddress = 0; StepAddress <= 0x7FFFFFFF; StepAddress += 0x10000)
    {
        ntStatus = ZwQueryVirtualMemory(HandleProcess,
                                        (PVOID)StepAddress, 
                                        MemoryBasicInformation,
                                        &BasicInformation, 
                                        sizeof(MEMORY_BASIC_INFORMATION), 
                                        &ReturnLength);

        if (!NT_SUCCESS(ntStatus) || BasicInformation.Type != SEC_IMAGE)  continue;
_Retry:        
        ntStatus = ZwQueryVirtualMemory(HandleProcess, 
                                        (PVOID)StepAddress, 
                                        MemorySectionName,                       
                                        SectionName, 
                                        BufferSize, 
                                        &ReturnLength);

        if (!NT_SUCCESS(ntStatus)) {
            if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
                ExFreePoolWithTag(SectionName, MEM_TAG);
                SectionName = ExAllocatePoolWithTag(PagedPool, ReturnLength, MEM_TAG);
                goto _Retry;
            }
            continue;
        }
        __try {
            if (memcmp(LastImageName, SectionName->SectionFileName.Buffer, 
                       SectionName->SectionFileName.Length) &&
                SectionName->SectionFileName.Length < 520) {

                memcpy(LastImageName, SectionName->SectionFileName.Buffer,
                       SectionName->SectionFileName.Length);
                LastImageName[SectionName->SectionFileName.Length / 2] = L'/0';

                //
                // Step into and get the image size
                //
                for (Step2Address = StepAddress + BasicInformation.RegionSize;
                     Step2Address < 0x7FFFFFFF; 
                     Step2Address += BasicInformation.RegionSize) {

                    ntStatus = ZwQueryVirtualMemory(HandleProcess, 
                                                    (PVOID)Step2Address,
                                                    MemoryBasicInformation, 
                                                    &BasicInformation, 
                                                    sizeof(MEMORY_BASIC_INFORMATION), 
                                                    &ReturnLength);
                    if (NT_SUCCESS(ntStatus) && 
                        BasicInformation.Type != SEC_IMAGE)  break;
                }
                
                FoundModule = ExAllocatePoolWithTag(NonPagedPool, sizeof(MODULE_INFO), MEM_TAG);
                FoundModule->BaseAddress = StepAddress;
                FoundModule->ImageSize = Step2Address - StepAddress;
                RtlStringCbPrintfW(FoundModule->ImagePath, 520, L"%s", LastImageName);
                
                InsertTailList(&g_ModuleListHead->ModuleListHead, &FoundModule->ModuleLink);
                g_ModuleListHead->NumberOfModules ++;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }    
    }
    ExFreePoolWithTag(SectionName, MEM_TAG);
    ObCloseHandle(HandleProcess, ExGetPreviousMode());
_End:
    KeSetEvent(&ThreadContext->SynEvent, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
```
　　此时的模块名是NT Path需要转成Dos Path，代码如下
```cpp
BOOLEAN NtPathToDosPathW(WCHAR* wzFullNtPath,WCHAR* wzFullDosPath);
extern
    NTSTATUS
    NTAPI
    ZwQueryDirectoryObject (
    __in HANDLE DirectoryHandle,
    __out_bcount_opt(Length) PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in BOOLEAN RestartScan,
    __inout PULONG Context,
    __out_opt PULONG ReturnLength
    );

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;


ULONG
    NtQueryDosDevice(WCHAR* wzDosDevice,WCHAR* wzNtDevice,
    ULONG ucchMax);
```

```cpp
BOOLEAN NtPathToDosPathW(WCHAR* wzFullNtPath,WCHAR* wzFullDosPath)
{
    WCHAR wzDosDevice[4] = {0};
    WCHAR wzNtDevice[64] = {0};
    WCHAR *RetStr = NULL;
    size_t NtDeviceLen = 0;
    short i = 0;
    if(!wzFullNtPath||!wzFullDosPath)
    {
        return FALSE;
    }
    for(i=65;i<26+65;i++)
    {
        wzDosDevice[0] = i;
        wzDosDevice[1] = L':';
        if(NtQueryDosDevice(wzDosDevice,wzNtDevice,64))
        {
            if(wzNtDevice)
            {
                NtDeviceLen = wcslen(wzNtDevice);
                if(!_wcsnicmp(wzNtDevice,wzFullNtPath,NtDeviceLen))
                {
                    wcscpy(wzFullDosPath,wzDosDevice);
                    wcscat(wzFullDosPath,wzFullNtPath+NtDeviceLen);
                    return TRUE;
                }
            }
        }
    }
}

ULONG
    NtQueryDosDevice(WCHAR* wzDosDevice,WCHAR* wzNtDevice,
    ULONG ucchMax)
{
    NTSTATUS Status;
    POBJECT_DIRECTORY_INFORMATION ObjectDirectoryInfor;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    HANDLE hDirectory;
    HANDLE hDevice;
    ULONG  ulReturnLength;
    ULONG  ulNameLength;
    ULONG  ulLength;
    ULONG       Context;
    BOOLEAN     bRestartScan;
    WCHAR*      Ptr = NULL;
    UCHAR       szBuffer[512] = {0};
    RtlInitUnicodeString (&uniString,L"\\??");
    InitializeObjectAttributes(&oa,
        &uniString,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL); 
    Status = ZwOpenDirectoryObject(&hDirectory,DIRECTORY_QUERY,&oa);
    if(!NT_SUCCESS(Status))
    {
        return 0;
    }
    ulLength = 0;
    if (wzDosDevice != NULL)
    {
        RtlInitUnicodeString (&uniString,(PWSTR)wzDosDevice);
        InitializeObjectAttributes(&oa,&uniString,OBJ_CASE_INSENSITIVE,hDirectory,NULL);
        Status = ZwOpenSymbolicLinkObject(&hDevice,GENERIC_READ,&oa);
        if(!NT_SUCCESS (Status))
        {
            ZwClose(hDirectory);
            return 0;
        }
        uniString.Length = 0;
        uniString.MaximumLength = (USHORT)ucchMax * sizeof(WCHAR);
        uniString.Buffer = wzNtDevice;
        ulReturnLength = 0;
        Status = ZwQuerySymbolicLinkObject (hDevice,&uniString,&ulReturnLength);
        ZwClose(hDevice);
        ZwClose(hDirectory);
        if (!NT_SUCCESS (Status))
        {
            return 0;
        }
        ulLength = uniString.Length / sizeof(WCHAR);
        if (ulLength < ucchMax)
        {
            wzNtDevice[ulLength] = UNICODE_NULL;
            ulLength++;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        bRestartScan = TRUE;
        Context = 0;
        Ptr = wzNtDevice;
        ObjectDirectoryInfor = (POBJECT_DIRECTORY_INFORMATION)szBuffer;
        while (TRUE)
        {
            Status = ZwQueryDirectoryObject(hDirectory,szBuffer,sizeof (szBuffer),TRUE,bRestartScan,&Context,&ulReturnLength);
            if(!NT_SUCCESS(Status))
            {
                if (Status == STATUS_NO_MORE_ENTRIES)
                {
                    *Ptr = UNICODE_NULL;
                    ulLength++;
                    Status = STATUS_SUCCESS;
                }
                else
                {
                    ulLength = 0;
                }
                break;
            }
            if (!wcscmp (ObjectDirectoryInfor->TypeName.Buffer, L"SymbolicLink"))
            {
                ulNameLength = ObjectDirectoryInfor->Name.Length / sizeof(WCHAR);
                if (ulLength + ulNameLength + 1 >= ucchMax)
                {
                    ulLength = 0;
                    break;
                }
                memcpy(Ptr,ObjectDirectoryInfor->Name.Buffer,ObjectDirectoryInfor->Name.Length);
                Ptr += ulNameLength;
                ulLength += ulNameLength;
                *Ptr = UNICODE_NULL;
                Ptr++;
                ulLength++;
            }
            bRestartScan = FALSE;
        }
        ZwClose(hDirectory);
    }
    return ulLength;
}
```
## 0x03 参考
[http://www.cnblogs.com/kedebug/archive/2010/12/22/2791753.html](http://www.cnblogs.com/kedebug/archive/2010/12/22/2791753.html)