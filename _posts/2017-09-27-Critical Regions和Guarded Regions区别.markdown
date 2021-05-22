---
layout: post
title: Critical Regions和Guarded Regions区别
date: 2017-09-18 09:45:12 +0900
category: windowsDriver
---
KeEnterCriticalRegion和KeLeaveCriticalRegion配合使用，能禁止用户模式APC和普通内核模式APC的调用，但是不能禁止特殊内核模式的调用(NormalRoutine为空的内核模式APC)

 

KeEnterGuardedRegion和KeLeaveGuardedRegion能禁止所有APC调用

 

KeEnterCriticalRegion会调用KeEnterCriticalRegionThread()函数，再看看KeEnterCriticalRegionThread()的内部实现

```cpp
FORCEINLINE
VOID
KeEnterCriticalRegionThread (
    PKTHREAD Thread
    )

/*++

Routine Description:

    This function disables kernel APC's for the current thread.

    N.B. The following code does not require any interlocks. There are
         two cases of interest: 1) On an MP system, the thread cannot
         be running on two processors as once, and 2) if the thread is
         is interrupted to deliver a kernel mode APC which also calls
         this routine, the values read and stored will stack and unstack
         properly.

Arguments:

    Thread - Supplies a pointer to the current thread.

    N.B. This must be a pointer to the current thread.

Return Value:

    None.

--*/

{

    ASSERT(Thread == KeGetCurrentThread());

    ASSERT((Thread->KernelApcDisable <= 0) && (Thread->KernelApcDisable != -32768));

    Thread->KernelApcDisable -= 1;
    KeMemoryBarrierWithoutFence();
    return;
}
```

KeEnterGuardRegion会调用KeEnterGuardRegionThread()函数，再看看KeEnterGuardRegionThread()的内部实现

```cpp
FORCEINLINE
VOID
KeEnterGuardedRegionThread (
    IN PKTHREAD Thread
    )

/*++

Routine Description:

    This function disables special kernel APC's for the current thread.

    N.B. The following code does not require any interlocks. There are
         two cases of interest: 1) On an MP system, the thread cannot
         be running on two processors as once, and 2) if the thread is
         is interrupted to deliver a kernel mode APC which also calls
         this routine, the values read and stored will stack and unstack
         properly.

Arguments:

    Thread - Supplies a pointer to the current thread.

    N.B. This must be a pointer to the current thread.

Return Value:

    None.

--*/

{

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    ASSERT(Thread == KeGetCurrentThread());

    ASSERT((Thread->SpecialApcDisable <= 0) && (Thread->SpecialApcDisable != -32768));

    Thread->SpecialApcDisable -= 1;
    KeMemoryBarrierWithoutFence();
    return;
}
```

注意两者之间的区别

KeEnterCriticalRegionThread中为

Thread->KernelApcDisable -= 1;

KeEnterGuardRegionThread中为

Thread->SpecialApcDisable -= 1;

再看看这里的改变会对APC的派发有什么影响，查看KiDeliverApc函数代码

```cpp
VOID
KiDeliverApc (
    IN KPROCESSOR_MODE PreviousMode,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PKTRAP_FRAME TrapFrame
    )

/*++

Routine Description:

    This function is called from the APC interrupt code and when one or
    more of the APC pending flags are set at system exit and the previous
    IRQL is zero. All special kernel APC's are delivered first, followed
    by normal kernel APC's if one is not already in progress, and finally
    if the user APC queue is not empty, the user APC pending flag is set,
    and the previous mode is user, then a user APC is delivered. On entry
    to this routine IRQL is set to APC_LEVEL.

    N.B. The exception frame and trap frame addresses are only guaranteed
         to be valid if, and only if, the previous mode is user.

Arguments:

    PreviousMode - Supplies the previous processor mode.

    ExceptionFrame - Supplies a pointer to an exception frame.

    TrapFrame - Supplies a pointer to a trap frame.

Return Value:

    None.

--*/

{

    PKAPC Apc;
    PKKERNEL_ROUTINE KernelRoutine;
    KLOCK_QUEUE_HANDLE LockHandle;
    PLIST_ENTRY NextEntry;
    PVOID NormalContext;
    PKNORMAL_ROUTINE NormalRoutine;
    PKTRAP_FRAME OldTrapFrame;
    PKPROCESS Process;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    PKTHREAD Thread;

    //
    // If the thread was interrupted in the middle of the SLIST pop code,
    // then back up the PC to the start of the SLIST pop. 
    //

    if (TrapFrame != NULL) {
        KiCheckForSListAddress(TrapFrame);
    }

    //
    // Save the current thread trap frame address and set the thread trap
    // frame address to the new trap frame. This will prevent a user mode
    // exception from being raised within an APC routine.
    //

    Thread = KeGetCurrentThread();
    OldTrapFrame = Thread->TrapFrame;
    Thread->TrapFrame = TrapFrame;

    //
    // If special APC are not disabled, then attempt to deliver one or more
    // APCs.
    //

    Process = Thread->ApcState.Process;
    Thread->ApcState.KernelApcPending = FALSE;
    if (Thread->SpecialApcDisable == 0) {

        //
        // If the kernel APC queue is not empty, then attempt to deliver a
        // kernel APC.
        //
        // N.B. The following test is not synchronized with the APC insertion
        //      code. However, when an APC is inserted in the kernel queue of
        //      a running thread an APC interrupt is requested. Therefore, if
        //      the following test were to falsely return that the kernel APC
        //      queue was empty, an APC interrupt would immediately cause this
        //      code to be executed a second time in which case the kernel APC
        //      queue would found to contain an entry.
        //

        KeMemoryBarrier();
        while (IsListEmpty(&Thread->ApcState.ApcListHead[KernelMode]) == FALSE) {

            //
            // Raise IRQL to dispatcher level, lock the APC queue, and check
            // if any kernel mode APC's can be delivered.
            //
            // If the kernel APC queue is now empty because of the removal of
            // one or more entries, then release the APC lock, and attempt to
            // deliver a user APC.
            //

            KeAcquireInStackQueuedSpinLock(&Thread->ApcQueueLock, &LockHandle);
            NextEntry = Thread->ApcState.ApcListHead[KernelMode].Flink;
            if (NextEntry == &Thread->ApcState.ApcListHead[KernelMode]) {
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                break;
            }

            //
            // Clear kernel APC pending, get the address of the APC object,
            // and determine the type of APC.
            //
            // N.B. Kernel APC pending must be cleared each time the kernel
            //      APC queue is found to be non-empty.
            //

            Thread->ApcState.KernelApcPending = FALSE;
            Apc = CONTAINING_RECORD(NextEntry, KAPC, ApcListEntry);
            ReadForWriteAccess(Apc);
            KernelRoutine = Apc->KernelRoutine;
            NormalRoutine = Apc->NormalRoutine;
            NormalContext = Apc->NormalContext;
            SystemArgument1 = Apc->SystemArgument1;
            SystemArgument2 = Apc->SystemArgument2;
            if (NormalRoutine == (PKNORMAL_ROUTINE)NULL) {
    
                //
                // First entry in the kernel APC queue is a special kernel APC.
                // Remove the entry from the APC queue, set its inserted state
                // to FALSE, release dispatcher database lock, and call the kernel
                // routine. On return raise IRQL to dispatcher level and lock
                // dispatcher database lock.
                //
    
                RemoveEntryList(NextEntry);
                Apc->Inserted = FALSE;
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                (KernelRoutine)(Apc,
                                &NormalRoutine,
                                &NormalContext,
                                &SystemArgument1,
                                &SystemArgument2);
    
#if DBG
    
                if (KeGetCurrentIrql() != LockHandle.OldIrql) {
                    KeBugCheckEx(IRQL_UNEXPECTED_VALUE,
                                 KeGetCurrentIrql() << 16 | LockHandle.OldIrql << 8,
                                 (ULONG_PTR)KernelRoutine,
                                 (ULONG_PTR)Apc,
                                 (ULONG_PTR)NormalRoutine);
                }
    
#endif

            } else {
    
                //
                // First entry in the kernel APC queue is a normal kernel APC.
                // If there is not a normal kernel APC in progress and kernel
                // APC's are not disabled, then remove the entry from the APC
                // queue, set its inserted state to FALSE, release the APC queue
                // lock, call the specified kernel routine, set kernel APC in
                // progress, lower the IRQL to zero, and call the normal kernel
                // APC routine. On return raise IRQL to dispatcher level, lock
                // the APC queue, and clear kernel APC in progress.
                //
    
                if ((Thread->ApcState.KernelApcInProgress == FALSE) &&
                   (Thread->KernelApcDisable == 0)) {

                    RemoveEntryList(NextEntry);
                    Apc->Inserted = FALSE;
                    KeReleaseInStackQueuedSpinLock(&LockHandle);
                    (KernelRoutine)(Apc,
                                    &NormalRoutine,
                                    &NormalContext,
                                    &SystemArgument1,
                                    &SystemArgument2);
    
#if DBG
    
                    if (KeGetCurrentIrql() != LockHandle.OldIrql) {
                        KeBugCheckEx(IRQL_UNEXPECTED_VALUE,
                                     KeGetCurrentIrql() << 16 | LockHandle.OldIrql << 8 | 1,
                                     (ULONG_PTR)KernelRoutine,
                                     (ULONG_PTR)Apc,
                                     (ULONG_PTR)NormalRoutine);
                    }
    
#endif
    
                    if (NormalRoutine != (PKNORMAL_ROUTINE)NULL) {
                        Thread->ApcState.KernelApcInProgress = TRUE;
                        KeLowerIrql(0);
                        (NormalRoutine)(NormalContext,
                                        SystemArgument1,
                                        SystemArgument2);
    
                        KeRaiseIrql(APC_LEVEL, &LockHandle.OldIrql);
                    }
    
                    Thread->ApcState.KernelApcInProgress = FALSE;
    
                } else {
                    KeReleaseInStackQueuedSpinLock(&LockHandle);
                    goto CheckProcess;
                }
            }
        }

        //
        // Kernel APC queue is empty. If the previous mode is user, user APC
        // pending is set, and the user APC queue is not empty, then remove
        // the first entry from the user APC queue, set its inserted state to
        // FALSE, clear user APC pending, release the dispatcher database lock,
        // and call the specified kernel routine. If the normal routine address
        // is not NULL on return from the kernel routine, then initialize the
        // user mode APC context and return. Otherwise, check to determine if
        // another user mode APC can be processed.
        //
        // N.B. There is no race condition associated with checking the APC
        //      queue outside the APC lock. User APCs are always delivered at
        //      system exit and never interrupt the execution of the thread
        //      in the kernel.
        //
    
        if ((PreviousMode == UserMode) &&
            (IsListEmpty(&Thread->ApcState.ApcListHead[UserMode]) == FALSE) &&
            (Thread->ApcState.UserApcPending != FALSE)) {

            //
            // Raise IRQL to dispatcher level, lock the APC queue, and deliver
            // a user mode APC.
            //

            KeAcquireInStackQueuedSpinLock(&Thread->ApcQueueLock, &LockHandle);

            //
            // If the user APC queue is now empty because of the removal of
            // one or more entries, then release the APC lock and exit.
            //

            Thread->ApcState.UserApcPending = FALSE;
            NextEntry = Thread->ApcState.ApcListHead[UserMode].Flink;
            if (NextEntry == &Thread->ApcState.ApcListHead[UserMode]) {
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                goto CheckProcess;
            }

            Apc = CONTAINING_RECORD(NextEntry, KAPC, ApcListEntry);
            ReadForWriteAccess(Apc);
            KernelRoutine = Apc->KernelRoutine;
            NormalRoutine = Apc->NormalRoutine;
            NormalContext = Apc->NormalContext;
            SystemArgument1 = Apc->SystemArgument1;
            SystemArgument2 = Apc->SystemArgument2;
            RemoveEntryList(NextEntry);
            Apc->Inserted = FALSE;
            KeReleaseInStackQueuedSpinLock(&LockHandle);
            (KernelRoutine)(Apc,
                            &NormalRoutine,
                            &NormalContext,
                            &SystemArgument1,
                            &SystemArgument2);
    
            if (NormalRoutine == (PKNORMAL_ROUTINE)NULL) {
                KeTestAlertThread(UserMode);
    
            } else {
                KiInitializeUserApc(ExceptionFrame,
                                    TrapFrame,
                                    NormalRoutine,
                                    NormalContext,
                                    SystemArgument1,
                                    SystemArgument2);
            }
        }
    }

    //
    // Check if process was attached during the APC routine.
    //

CheckProcess:
    if (Thread->ApcState.Process != Process) {
        KeBugCheckEx(INVALID_PROCESS_ATTACH_ATTEMPT,
                     (ULONG_PTR)Process,
                     (ULONG_PTR)Thread->ApcState.Process,
                     (ULONG)Thread->ApcStateIndex,
                     (ULONG)KeIsExecutingDpc());
    }

    //
    // Restore the previous thread trap frame address.
    //

    Thread->TrapFrame = OldTrapFrame;
    return;
}
```

可以看到，这个函数会判断Thread->SpecialApcDisable 和 Thread->KernelApcSidable 的值，如果Thread->SpecialApcDisable 为0，会先派发特殊内核APC，然后判断Thread->KernelApcDisable是否为0，为0 就去进一步的派发普通内核 Apc和 用户Apc

 

参考：[https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/critical-regions-and-guarded-regions](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/critical-regions-and-guarded-regions)
