---
layout: post
title: Win7 x64下进程保护与文件保护(ObRegisterCallbacks)
date: 2016-05-07 12:49:12 +0900
category: windowsDriver
---
进程保护部分参考 [http://bbs.pediy.com/showthread.php?t=168023](http://bbs.pediy.com/showthread.php?t=168023)

进程保护，在任务管理器不能结束进程

```cpp
#ifndef CXX_PROTECTPROCESSX64_H
#define CXX_PROTECTPROCESSX64_H

#include <ntifs.h>

#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

extern 
    UCHAR *
    PsGetProcessImageFileName(
    __in PEPROCESS Process
    );
char*
    GetProcessImageNameByProcessID(ULONG ulProcessID);

NTSTATUS ProtectProcess(BOOLEAN Enable);

OB_PREOP_CALLBACK_STATUS 
    preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

#endif    







#ifndef CXX_PROTECTPROCESSX64_H
#    include "ProtectProcessx64.h"
#endif


PVOID obHandle;//定义一个void*类型的变量，它将会作为ObRegisterCallbacks函数的第二个参数。

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLDR_DATA_TABLE_ENTRY64 ldr;

    pDriverObj->DriverUnload = DriverUnload;
    // 绕过MmVerifyCallbackFunction。
    ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
    ldr->Flags |= 0x20;

    ProtectProcess(TRUE);

    return STATUS_SUCCESS;
}



NTSTATUS ProtectProcess(BOOLEAN Enable)
{

    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg;

    memset(&obReg, 0, sizeof(obReg));
    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");
    memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

    //下面请注意这个结构体的成员字段的设置
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE|OB_OPERATION_HANDLE_DUPLICATE; 

    opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; //在这里注册一个回调函数指针

    obReg.OperationRegistration = &opReg; //注意这一条语句

    return ObRegisterCallbacks(&obReg, &obHandle); //在这里注册回调函数
}


OB_PREOP_CALLBACK_STATUS 
    preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
    HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
    char szProcName[16]={0};
    UNREFERENCED_PARAMETER(RegistrationContext);
    strcpy(szProcName,GetProcessImageNameByProcessID((ULONG)pid));
    if( !_stricmp(szProcName,"calc.exe") )
    {
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
            {
                //Terminate the process, such as by calling the user-mode TerminateProcess routine..
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            }
            if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
            {
                //Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            }
            if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
            {
                //Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            }
            if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
            {
                //Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            }
        }
    }
    return OB_PREOP_SUCCESS;
}


/*
OpenProcess 会一直走入回调中  直接蓝屏
char*
    GetProcessImageNameByProcessID(ULONG ulProcessID)
{
    CLIENT_ID Cid;    
    HANDLE    hProcess;
    NTSTATUS  Status;
    OBJECT_ATTRIBUTES  oa;
    PEPROCESS  EProcess = NULL;

    Cid.UniqueProcess = (HANDLE)ulProcessID;
    Cid.UniqueThread = 0;

    InitializeObjectAttributes(&oa,0,0,0,0);
    Status = ZwOpenProcess(&hProcess,PROCESS_ALL_ACCESS,&oa,&Cid);    //hProcess
    //强打开进程获得句柄
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }
    Status = ObReferenceObjectByHandle(hProcess,FILE_READ_DATA,0,
        KernelMode,&EProcess, 0);
    //通过句柄括获取EProcess
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hProcess);
        return FALSE;
    }
    ObDereferenceObject(EProcess);
    //最好判断
    ZwClose(hProcess);
    //通过EProcess获得进程名称
    return (char*)PsGetProcessImageFileName(EProcess);     
    
}
*/




char*
    GetProcessImageNameByProcessID(ULONG ulProcessID)
{
    NTSTATUS  Status;
    PEPROCESS  EProcess = NULL;

    
    Status = PsLookupProcessByProcessId((HANDLE)ulProcessID,&EProcess);    //EPROCESS

    //通过句柄获取EProcess
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }
    ObDereferenceObject(EProcess);
    //通过EProcess获得进程名称
    return (char*)PsGetProcessImageFileName(EProcess);     

}



VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{    
    UNREFERENCED_PARAMETER(pDriverObj);
    DbgPrint("driver unloading...\n");

    ObUnRegisterCallbacks(obHandle); //obHandle是上面定义的 PVOID obHandle;
}
```
我们使用任务管理器结束进程

![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-05-07/1.png)

 结果是不能关闭的

![2](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-05-07/2.png)

文件保护

```cpp
#ifndef CXX_FILEPROTECTX64_H
#define CXX_FILEPROTECTX64_H
#include <ntifs.h>
#include <devioctl.h>
NTSTATUS
    DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath);
VOID UnloadDriver(PDRIVER_OBJECT  DriverObject);
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                        
{
    UINT16       Length;
    union                                                                                                                                                                       
    {
        UINT8        ObjectTypeFlags;
        struct                                                                                                                                                                
        {
            UINT8        CaseInsensitive : 1;                                                                                     UINT8        UnnamedObjectsOnly : 1;                                                                                  UINT8        UseDefaultObject : 1;                                                                                    UINT8        SecurityRequired : 1;                                                                                    UINT8        MaintainHandleCount : 1;                                                                                 UINT8        MaintainTypeList : 1;                                                                                    UINT8        SupportsObjectCallbacks : 1;                                                                                                                         
        };
    };
    ULONG32      ObjectTypeCode;
    ULONG32      InvalidAttributes;
    struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     
    ULONG32      ValidAccessMask;
    ULONG32      RetainAccess;
    enum _POOL_TYPE PoolType;
    ULONG32      DefaultPagedPoolCharge;
    ULONG32      DefaultNonPagedPoolCharge;
    PVOID        DumpProcedure;
    PVOID        OpenProcedure;
    PVOID         CloseProcedure;
    PVOID         DeleteProcedure;
    PVOID         ParseProcedure;
    PVOID        SecurityProcedure;
    PVOID         QueryNameProcedure;
    PVOID         OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE_TEMP                   
{
    struct _LIST_ENTRY TypeList;             
    struct _UNICODE_STRING Name;             
    VOID*        DefaultObject;
    UINT8        Index;
    UINT8        _PADDING0_[0x3];
    ULONG32      TotalNumberOfObjects;
    ULONG32      TotalNumberOfHandles;
    ULONG32      HighWaterNumberOfObjects;
    ULONG32      HighWaterNumberOfHandles;
    UINT8        _PADDING1_[0x4];
    struct _OBJECT_TYPE_INITIALIZER TypeInfo; 
    ULONG64 TypeLock;          
    ULONG32      Key;
    UINT8        _PADDING2_[0x4];
    struct _LIST_ENTRY CallbackList;        
}OBJECT_TYPE_TEMP, *POBJECT_TYPE_TEMP;

VOID EnableObType(POBJECT_TYPE ObjectType);
UNICODE_STRING  GetFilePathByFileObject(PVOID FileObject);
OB_PREOP_CALLBACK_STATUS PreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
NTSTATUS ProtectFileByObRegisterCallbacks();
#endif    











#ifndef CXX_FILEPROTECTX64_H
#    include "FileProtectX64.h"
#endif
PVOID  CallBackHandle = NULL;
NTSTATUS
    DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegisterPath)
{    

    PLDR_DATA_TABLE_ENTRY64 ldr;
    DriverObject->DriverUnload = UnloadDriver;
    ldr = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
    ldr->Flags |= 0x20;
    ProtectFileByObRegisterCallbacks();
    return STATUS_SUCCESS;
}
NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION  CallBackReg;
    OB_OPERATION_REGISTRATION OperationReg;
    NTSTATUS  Status;
    
    EnableObType(*IoFileObjectType);      //开启文件对象回调
    memset(&CallBackReg, 0, sizeof(OB_CALLBACK_REGISTRATION));
    CallBackReg.Version = ObGetFilterVersion();
    CallBackReg.OperationRegistrationCount = 1;
    CallBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&CallBackReg.Altitude, L"321000");
    memset(&OperationReg, 0, sizeof(OB_OPERATION_REGISTRATION)); //初始化结构体变量


    OperationReg.ObjectType = IoFileObjectType;
    OperationReg.Operations = OB_OPERATION_HANDLE_CREATE|OB_OPERATION_HANDLE_DUPLICATE; 
    
    OperationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&PreCallBack; //在这里注册一个回调函数指针
    CallBackReg.OperationRegistration = &OperationReg; //注意这一条语句   将结构体信息放入大结构体
    Status = ObRegisterCallbacks(&CallBackReg, &CallBackHandle);     
    if (!NT_SUCCESS(Status)) 
    {
        Status = STATUS_UNSUCCESSFUL;
    } 
    else
    {
        Status = STATUS_SUCCESS;
    }
    return Status; 
}

OB_PREOP_CALLBACK_STATUS PreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNICODE_STRING uniDosName;
    UNICODE_STRING uniFilePath;
    PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
    HANDLE CurrentProcessId = PsGetCurrentProcessId();
    if( OperationInformation->ObjectType!=*IoFileObjectType)
    {
        return OB_PREOP_SUCCESS;
    }
    //过滤无效指针
    if(    FileObject->FileName.Buffer==NULL                || 
        !MmIsAddressValid(FileObject->FileName.Buffer)    ||
        FileObject->DeviceObject==NULL                    ||
        !MmIsAddressValid(FileObject->DeviceObject)        )
    {
        return OB_PREOP_SUCCESS;
    }
    uniFilePath = GetFilePathByFileObject(FileObject);
    if (uniFilePath.Buffer==NULL||uniFilePath.Length==0)
    {
        return OB_PREOP_SUCCESS;
    }
    if(wcsstr(uniFilePath.Buffer,L"D:\\Test.txt"))
    {
        if (FileObject->DeleteAccess==TRUE||FileObject->WriteAccess==TRUE)
        {
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
            }
            if(OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
            }
        }
    }
    RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName);
    DbgPrint("PID : %ld File : %wZ  %wZ\r\n", (ULONG64)CurrentProcessId, &uniDosName, &uniFilePath);
    return OB_PREOP_SUCCESS;
}
UNICODE_STRING  GetFilePathByFileObject(PVOID FileObject)
{
    POBJECT_NAME_INFORMATION ObjetNameInfor;  
    if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))  
    {  
        return ObjetNameInfor->Name;  
    }  
}
VOID EnableObType(POBJECT_TYPE ObjectType)  
{
    POBJECT_TYPE_TEMP  ObjectTypeTemp = (POBJECT_TYPE_TEMP)ObjectType;
    ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;
}
VOID UnloadDriver(PDRIVER_OBJECT  DriverObject)
{
    if (CallBackHandle!=NULL)
    {
        ObUnRegisterCallbacks(CallBackHandle);
    }
    DbgPrint("UnloadDriver\r\n");
}
```