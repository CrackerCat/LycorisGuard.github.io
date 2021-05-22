---
layout: post
title: PsLookupProcessByProcessId分析
date: 2016-03-13 11:00:12 +0900
category: windowsDriver
---

　　本文是在讨论枚举进程的时候产生的，枚举进程有很多方法，Ring3的方法就是ZwQuerySystemInformation()，传入SysProcessesAndThreadsInformation这个宏。无论是CreateToolhelp32Snapshot系统快照的方式枚举进程，还是是用WTSOpenServer这个第三方库的函数，最后都是调用ZwQuerySystemInformtaion()。Ring0就是进程活动链表，系统句柄表中枚举。然后就是PsLookupProcessByProcessId了。

　　NtOpenProcess -> PsProcessByProcessId ->关闭APC，调用ExMapHandleToPointer->调用ExpLookupHandleTableEntry找到HANDLE_TABLE_ENTRY在调用ExpLockHandleTableEntry锁定，判断是否调试状态，成功返回->PsProcessByProcessId之后增加引用计数，解锁APC，成功返回。

　　首先看一下函数原型
```cpp
NTSTATUS 
 PsLookupProcessByProcessId( 
     __in HANDLE ProcessId,   //进程ID
     __deref_out PEPROCESS *Process //返回的EPROCESS
 )
```
　　第一个参数是进程ID，第二个参数就是进程体了

　　下面我们从OD跟进这个函数

```cpp
 kd> u PsLookupProcessByProcessId l 20
  nt!PsLookupProcessByProcessId:
  805ca38a 8bff            mov     edi,edi
  805ca38c 55              push    ebp
  805ca38d 8bec            mov     ebp,esp
  805ca38f 53              push    ebx
  805ca390 56              push    esi
  805ca391 64a124010000    mov     eax,dword ptr fs:[00000124h]
  805ca397 ff7508          push    dword ptr [ebp+8]
  805ca39a 8bf0            mov     esi,eax
  805ca39c ff8ed4000000    dec     dword ptr [esi+0D4h]
  805ca3a2 ff3560b25580    push    dword ptr [nt!PspCidTable (8055b260)]
  805ca3a8 e84bb50300      call    nt!ExMapHandleToPointer (806058f8)
```

　　PsLookupProcessByHandle首先使APC无效
```cpp
    CurrentThread = PsGetCurrentThread ();
    KeEnterCriticalRegionThread (&CurrentThread->Tcb);　
```

　　然后调用了函数ExMapHandleToPointer函数，传入的参数就是PspCidTable系统句柄表的指针。
```cpp
    CidEntry = ExMapHandleToPointer(PspCidTable, ProcessId);
      if (CidEntry != NULL) {
          lProcess = (PEPROCESS)CidEntry->Object;
          if (lProcess->Pcb.Header.Type == ProcessObject &&
              lProcess->GrantedAccess != 0) {
              if (ObReferenceObjectSafe(lProcess)) {
                 *Process = lProcess;
                  Status = STATUS_SUCCESS;
              }
         }
 
         ExUnlockHandleTableEntry(PspCidTable, CidEntry);
     }
```
　　ExMapHandleToPointer函数调用了ExpLookupHandleTableEntry函数，但是在之前做了参数检查
```cpp
      LocalHandle.GenericHandleOverlay = Handle;  //会判断句柄的有效性
  
      HandleTableEntry = ExpLookupHandleTableEntry( HandleTable,
                                                    LocalHandle );
      if (HandleTableEntry == NULL) {
          return NULL;
     }
```
　　ExMapHandleToPointer调用ExpLookupHandleTableEntry所做的事情就是在句柄表的三层结构中找到对应的对象，返回HANDLE_TABLE_ENTRY结构，再返回之后就会调用ExpLockHandleTableEntry函数来锁定当前的HANDLE_TABLE_ENTRY
```cpp
      HandleTableEntry = ExpLookupHandleTableEntry( HandleTable, LocalHandle ); 
      if (HandleTableEntry == NULL) { return NULL; }
```
　　在ExpLockHandleTableEntry中就会调用InterlockedCompareExchangePointer，如果不成功，则可能是进程句柄处于被调试状态，可以通过HandleTableEntry中的debugInfo来判断句柄是否处于调试状态
```cpp
      if ((HandleTableEntry == NULL) ||
          !ExpLockHandleTableEntry( HandleTable, HandleTableEntry)) {
          //
          // If we are debugging handle operations then save away the details
          //
  
          if (HandleTable->DebugInfo != NULL) {
              ExpUpdateDebugInfo(HandleTable, PsGetCurrentThread (), Handle, HANDLE_TRACE_DB_BADREF);
          }
         return NULL;
     }
```
　　如果处于调试状态，则用ExpUpdateDebugInfo函数填充HANDLE_TRACE_DEBUG_INFO结构，保存调试信息，否则返回NULL，调用失败

　　当函数调用成功就返回到PsLookupProcessByProcessId中，将HANDLE_TABLE_ENTRY中的Object转化成EPROCESS对象，确保这个对象是ProcessObject且有继承权，则引用计数加1，
```cpp
      CidEntry = ExMapHandleToPointer(PspCidTable, ThreadId);
      Status = STATUS_INVALID_PARAMETER;
      if (CidEntry != NULL) {
          lThread = (PETHREAD)CidEntry->Object;
          if (lThread != (PETHREAD)PSP_INVALID_ID && lThread->Tcb.Header.Type == ThreadObject && lThread->GrantedAccess ) {
  
              ObReferenceObject(lThread);
              *Thread = lThread;
              Status = STATUS_SUCCESS;
         }
 
         ExUnlockHandleTableEntry(PspCidTable, CidEntry);
     }
```
　　然后装入参数EPROCESS，解锁当前的handle table entry，恢复当前内核线程的APC，成功返回。