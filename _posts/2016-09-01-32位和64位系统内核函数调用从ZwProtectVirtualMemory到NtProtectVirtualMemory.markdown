---
layout: post
title: 32位和64位系统内核函数调用从ZwProtectVirtualMemory到NtProtectVirtualMemory
date: 2016-09-01 01:42:12 +0900
category: windows
---
## 0x01 前言
　　我们知道R3层中，Zw系列函数和Nt系列函数函数是一样的，但是在内核Zw系列函数调用了Nt系列函数，但是为什么要在内核设置一个Zw系列函数而不是直接调用Nt函数呢？Zw系列函数又是怎么调用Nt系列函数的呢？我们利用IDA分析NtosKrnl.exe文件。

## 0x02 ZwProtectVirtualMemory

　　我们先看看ZwProtectVirtualMemory的实现
```cpp
.text:00406170 ; NTSTATUS __stdcall ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect)
.text:00406170 _ZwProtectVirtualMemory@20 proc near    ; CODE XREF: RtlpCreateStack(x,x,x,x,x)+FAp
.text:00406170
.text:00406170 ProcessHandle   = dword ptr  4
.text:00406170 BaseAddress     = dword ptr  8
.text:00406170 ProtectSize     = dword ptr  0Ch
.text:00406170 NewProtect      = dword ptr  10h
.text:00406170 OldProtect      = dword ptr  14h
.text:00406170
.text:00406170                 mov     eax, 89h  ;Nt函数的系统调用号
.text:00406175                 lea     edx, [esp+ProcessHandle] ;使用EDX指向堆栈上的参数块
.text:00406179                 pushf        ;EFLAGS
.text:0040617A                 push    8    ;CS   KGDT_R0_CODE
.text:0040617C                 call    _KiSystemService
.text:00406181                 retn    14h    ;5个参数，20字节
.text:00406181 _ZwProtectVirtualMemory@20 endp
```
　　这里89h为NtProtectVirtualMemory函数在SSDT函数中的调用号，CS寄存器，最后位为0表示当前处于内核态，然后调用KiSystemService函数

## 0x03 KiSystemService

　　我们接着看KiSystemService的函数实现
```cpp
.text:00407631 _KiSystemService proc near              ; CODE XREF: ZwAcceptConnectPort(x,x,x,x,x,x)+Cp
.text:00407631                                         ; ZwAccessCheck(x,x,x,x,x,x,x,x)+Cp ...
.text:00407631
.text:00407631 arg_0           = dword ptr  4
.text:00407631
.text:00407631                 push    0
.text:00407633                 push    ebp
.text:00407634                 push    ebx
.text:00407635                 push    esi
.text:00407636                 push    edi
.text:00407637                 push    fs              ; 保存用户空间的fs
.text:00407639                 mov     ebx, 30h        ; KGDT_R0_PCR
.text:0040763E                 mov     fs, ebx         ; 使FS段的起点与KPCR数据结构对齐
.text:00407640                 push    dword ptr ds:0FFDFF000h
.text:00407646                 mov     dword ptr ds:0FFDFF000h, 0FFFFFFFFh
.text:00407650                 mov     esi, ds:0FFDFF124h ; #define KPCR_CURRENT_THREAD 0x124
.text:00407650                                         ; 指向当前cpu正在运行的线程
.text:00407650                                         ; FS:0x124
.text:00407650                                         ; PCR的大小只有0x54，这里偏移到了KPRCB中的CurrentThread
.text:00407656                 push    dword ptr [esi+140h]
.text:0040765C                 sub     esp, 48h
.text:0040765F                 mov     ebx, [esp+68h+arg_0] ; 系统调用前夕的CS映像
.text:00407663                 and     ebx, 1          ; 0环的最低位为0，3环的最低位为1
.text:00407666                 mov     [esi+140h], bl  ; 新的"先前模式"  [esi+KTHREAD_PREVIOUS_MODE]
.text:0040766C                 mov     ebp, esp
.text:0040766E                 mov     ebx, [esi+134h] ; KTHREAD结构中的指针TrapFrame [esi+KTHREAD_TRAP_FRAME]
.text:00407674                 mov     [ebp+3Ch], ebx  ; 暂时保存在这里 [ebp+KTRAP_FRAME_EDX]
.text:00407677                 mov     [esi+134h], ebp ; 新的TrapFrame,指向堆栈上的框架 [esi+KTHREAD_TRAP_FRAME]
...
.text:0040769E                 sti
.text:0040769F                 jmp     loc_407781
.text:0040769F _KiSystemService endp
```
　　这里首先要在系统态堆栈上构建一个系统调用"框架Frame"，或称为"自陷框架"，其作用主要是用来保存发生自陷时CPU中各寄存器的"现场"，或者说"上下文"，以备返回用户空间时予以恢复。

　　Windows内核有个特殊的基本要求，只要CPU在内核运行，FS寄存器就指向一个KPCR的数据结构，FS的值为0x30，其0-1位为0，表示0环，第2位为0，表示GDT表，为1则表示LDT表，3-15位为6，表示在GDT的下标为6的表项中的地址即为KPCR的地址。KPCR是处理器控制块，在单处理器中只有一个KPCR，在多CPU的系统中，每个CPU都有自己的KPCR结构。

　　CPU从用户空间进入系统空间时会将当时寄存器CS的内容压入系统态堆栈，CS的最低位就可以说明当时运行于何种模式的标志位。这里取出CS最低位保存在ETHREAD的PREVIOUS_MODE上。

　　更新ETHREAD中的TrapFrame框架，保存旧的框架。

## 0x04 KiFastCallEntry

　　KiSystemService中的jmp loc_407781跳转到KiFastCallEntry函数中，代码如下：
```cpp
.text:004076F0 _KiFastCallEntry proc near              ; DATA XREF: _KiTrap01+6Fo
.text:004076F0                                         ; KiLoadFastSyscallMachineSpecificRegisters(x)+24o
.text:004076F0
.text:004076F0 var_B           = byte ptr -0Bh
.text:004076F0
.text:004076F0 ; FUNCTION CHUNK AT .text:004076C8 SIZE 00000023 BYTES
.text:004076F0 ; FUNCTION CHUNK AT .text:00407990 SIZE 00000014 BYTES
.text:004076F0
.text:004076F0                 mov     ecx, 23h        ;  KGDT_R3_DATA OR RPL_MASK
.text:004076F5                 push    30h
.text:004076F7                 pop     fs              ; 只要进入内核..fs->KPCR(Kernel's Processor Control Region,内核进程控制区域)
.text:004076F9                 mov     ds, ecx         ; 使用23h选择子
.text:004076FB                 mov     es, ecx
.text:004076FD                 mov     ecx, ds:0FFDFF040h ; _KPCR->_KTSS
.text:00407703                 mov     esp, [ecx+4]    ; 取出_KTSS->esp0
.text:00407703                                         ; 这里是模拟自陷框架,以形成和中断, 异常统一的框架 _KTRAP_FRAME
.text:00407706                 push    23h             ; KGDT_R3_DATA OR RPL_MASK
.text:00407708                 push    edx             ; R3 ss:esp
.text:00407709                 pushf                   ; R3 Eflags
.text:0040770A
.text:0040770A loc_40770A:                             ; CODE XREF: _KiFastCallEntry2+22j
.text:0040770A                 push    2
.text:0040770C                 add     edx, 8          ; edx -> args 用户态参数
.text:0040770F                 popf                    ; Eflags = 2 中断已关闭
.text:00407710                 or      [esp+0Ch+var_B], 2 ; 开启R3 Eflags的中断标记
.text:00407715                 push    1Bh             ; R3 cs:eip
.text:00407717                 push    dword ptr ds:0FFDF0304h ; ntdll!KiFastSystemCallRet
.text:0040771D                 push    0               ; 为了和中断保持一致, 中断会有错误码, 同时用于返回值
.text:0040771F                 push    ebp
.text:00407720                 push    ebx
.text:00407721                 push    esi
.text:00407722                 push    edi
.text:00407723                 mov     ebx, ds:0FFDFF01Ch ; ebx<-_KPCR.SelfPcr 这是pcr的指针
.text:00407729                 push    3Bh
.text:0040772B                 mov     esi, [ebx+124h] ; esi=_KPCR.PrcbData.CurrentThread _KTHREAD
.text:00407731                 push    dword ptr [ebx] ; 异常链表
.text:00407733                 mov     dword ptr [ebx], 0FFFFFFFFh ; 初始化链表
.text:00407739                 mov     ebp, [esi+18h]  ; 获取线程堆栈
.text:0040773C                 push    1               ; MODE_MASK = User Mode
.text:0040773E                 sub     esp, 48h        ; 分配剩余 _KTRAP_FRAME 框架
.text:00407741                 sub     ebp, 29Ch       ; (_FX_SAVE_AREA)NPX_FRAME_LENGTH=210h, (_KTRAP_FRAME)KTRAP_FRAME_LENGTH=8C
.text:00407747                 mov     byte ptr [esi+140h], 1 ; MODE_MASK = 1 设置线程模式
.text:00407747                                         ; 现在_KTRAP_FRAME已经建立完成
.text:00407747                                         ; 057
.text:00407747                                         ; 计算初始堆栈线程的初始堆栈指针,包含NPX和_KTRAP_FRAME
.text:00407747                                         ; 058
.text:00407747                                         ; 如果 ebp 和 esp 不相等, 那么这是一个V86模式的线程. 拒绝调用.
.text:0040774E                 cmp     ebp, esp
.text:00407750                 jnz     loc_4076C8      ; 处理V86模式的代码不看了.
.text:00407756                 and     dword ptr [ebp+2Ch], 0 ; 清空 Dr7 调试寄存器
.text:0040775A                 test    byte ptr [esi+2Ch], 0FFh ; 线程是否被调试状态
.text:0040775E                 mov     [esi+134h], ebp ; ebp = _KTRAP_FRAME 保存新的 TrapFrame
.text:00407764                 jnz     Dr_FastCallDrSave ; 如果线程被调试, 那么还要做些处理, 这里先不管.
.text:0040776A
.text:0040776A loc_40776A:                             ; CODE XREF: Dr_FastCallDrSave+10j
.text:0040776A                                         ; Dr_FastCallDrSave+7Cj
.text:0040776A                 mov     ebx, [ebp+60h]  ; ebx = _KTRAP_FRAME->Ebp
.text:0040776D                 mov     edi, [ebp+68h]  ; edi = _KTRAP_FRAME->Eip
.text:00407770                 mov     [ebp+0Ch], edx  ; edx = 参数指针
.text:00407773                 mov     dword ptr [ebp+8], 0BADB0D00h
.text:0040777A                 mov     [ebp+0], ebx    ; _KTRAP_FRAME.DbgEbp = _KTRAP_FRAME->Ebp
.text:0040777D                 mov     [ebp+4], edi    ; _KTRAP_FRAME.DbgEip = _KTRAP_FRAME->Eip
.text:00407780                 sti
.text:00407781
.text:00407781 loc_407781:                             ; CODE XREF: _KiBBTUnexpectedRange+18j
.text:00407781                                         ; _KiSystemService+6Ej
.text:00407781                 mov     edi, eax        ; 系统调用号
.text:00407783                 shr     edi, 8          ; NtProtectVirtualMemory 89h = 10001001
.text:00407783                                         ; shr右移8位为0
.text:00407783                                         ; Shadow SSDT函数索引都在0x1000以上
.text:00407786                 and     edi, 30h
.text:00407789                 mov     ecx, edi        ; 如果是shadow ecx = 10h，否则ecx =0h (bit11 bit12)
.text:0040778B                 add     edi, [esi+0E0h] ; 确定是哪个表
.text:0040778B                                         ; 本线程的系统调用表
.text:0040778B                                         ; EDI指向描述块0或描述块1
.text:00407791                 mov     ebx, eax        ; 将eax中的索引值，赋值给ebx
.text:00407793                 and     eax, 0FFFh      ; SERVICE_NUMBER_MASK定义为0xFFF
.text:00407798                 cmp     eax, [edi+8]    ; 检查系统调用号是否越界
.text:00407798                                         ; SERVICE_DESCRIPTOR_LIMIT定义为8
.text:0040779B                 jnb     _KiBBTUnexpectedRange ; 系统调用号越界，超过SSDT表中的Number
```
　　我们这里是直接跳转到loc_407781的地方，再此之前的代码是通过用户层调用Native API的时候进行的处理。

　　这里eax保存着系统调用号，在KTHREAD中有一个指针ServiceTable，如果是gui线程则指向KeServiceDescriptorTableShadow[]，如果不是则指向KeServiceDescriptor[]。这里检查了系统调用号是否越界。多数情况下不会越界，我们继续往下看：

```cpp
.text:004077A1                 cmp     ecx, 10h        ; 测试是否调用 Shadow Ssdt
.text:004077A4                 jnz     short NotWin32K ; 不跳则是shadow
.text:004077A6                 mov     ecx, ds:0FFDFF018h ;  ecx = _KPCR->_NT_TIB->Self 指向 _TEB
.text:004077AC                 xor     ebx, ebx
.text:004077AE
.text:004077AE loc_4077AE:                             ; DATA XREF: _KiTrap0E+110o
.text:004077AE                 or      ebx, [ecx+0F70h] ; _TEB.GdiBatchCount
.text:004077B4                 jz      short NotWin32K
.text:004077B6                 push    edx             ; edx = argc
.text:004077B7                 push    eax             ; eax = Index
.text:004077B8                 call    ds:_KeGdiFlushUserBatch
.text:004077BE                 pop     eax             ; eax = Index
.text:004077BF                 pop     edx             ; edx  = argc
.text:004077C0
.text:004077C0 NotWin32K:                              ; CODE XREF: _KiFastCallEntry+B4j
.text:004077C0                                         ; _KiFastCallEntry+C4j
.text:004077C0                 inc     dword ptr ds:0FFDFF638h ; _KPRCB->KeSystemCalls++, 记录系统调用次数
.text:004077C6                 mov     esi, edx        ; 使ESI指向用户空间堆栈上的参数块
.text:004077C8                 mov     ebx, [edi+0Ch]  ; ebx = ssdt->ParamTableBase
.text:004077C8                                         ; [edi+SERVICE_DESCRIPTOR_NUMBER]
.text:004077CB                 xor     ecx, ecx
.text:004077CD                 mov     cl, [eax+ebx]   ; 寄存器ECX  cl = 参数总共占得字节大小
.text:004077D0                 mov     edi, [edi]      ; edi=ssdt->ServiceTableBase
.text:004077D0                                         ; EDI指向具体的系统调用表
.text:004077D0                                         ; [edi+SERVICE_DESCRIPTOR_BASE]
.text:004077D2                 mov     ebx, [edi+eax*4] ; 函数指针
.text:004077D5                 sub     esp, ecx        ; 系统堆栈上留出空间
.text:004077D7                 shr     ecx, 2          ; 除4,参数个数
.text:004077DA                 mov     edi, esp        ; edi = 内核栈的参数位置
.text:004077DC                 cmp     esi, ds:_MmUserProbeAddress ; 参数块的位置不得高于MmSystemRangeStart-0x10000
.text:004077E2                 jnb     AccessViolation
.text:004077E8
.text:004077E8 loc_4077E8:                             ; CODE XREF: _KiFastCallEntry+2A4j
.text:004077E8                                         ; DATA XREF: _KiTrap0E+106o
.text:004077E8                 rep movsd               ; 复制参数，以ESI为源，EDI为目标，ECX为循环次数
.text:004077E8                                         ; ecx是参数个数,从用户栈复制参数到内核栈,原来SSDT所有参数都是4个字节为单位的.
.text:004077EA                 call    ebx             ; 调用目标函数
```
　　这里将ECX与0x10比较，如果不是0x10则为基本调用表(SSDT函数)，转到NotWin32K处。这里ecx的cl保存着KSERVICE_TABLE_DESCRIPTOR结构体中的Number，将cl右移2位就是参数的个数，后面重复执行的movsd的次数就是参数的个数，不过复制之前要调整堆栈指针，将ESP与移位前的ECX相减，在系统空间堆栈上 空出相应的字节数。注意movsd指令以ESI所指处为源，以EDI所指处为目标，另一方面，指令获得函数的指针赋值为ebx，最后call ebx实现了对目标函数的调用。

　　一些安全软件对KiFastCallEntry通过Hook实现过滤SSDT框架的时候，通常是在ebx完成赋值之后，在call ebx之前，替换这中间的地方，进入fake1函数，将保存好的参数push，比如edi保存的SSDT表地址，ebx保存函数地址，eax保存调用号，ecx保存参数个数，在这中间hook，可以直接利用系统初始化好的寄存器，然后调用filter函数，通过寄存器的值，过滤指定的SSDT函数，替换ebx的值，然后继续执行KiFastCallEntry中的call ebx，这样就可以过滤整个SSDT系统调用了。

　　当执行完成call ebx，从目标函数返回时我们继续看下面的指令：

```cpp
.text:004077EC
.text:004077EC loc_4077EC:                             ; CODE XREF: _KiFastCallEntry+2AFj
.text:004077EC                                         ; DATA XREF: _KiTrap0E+126o ...
.text:004077EC                 mov     esp, ebp        ; 恢复栈顶,此时栈顶是KTRAP_FRAME
.text:004077EE
.text:004077EE KeReturnFromSystemCall:                 ; CODE XREF: _KiBBTUnexpectedRange+38j
.text:004077EE                                         ; _KiBBTUnexpectedRange+43j
.text:004077EE                 mov     ecx, ds:0FFDFF124h ; ecx = _KTHREAD
.text:004077F4                 mov     edx, [ebp+3Ch]  ; edx = KTRAP_FRAME->Edx
.text:004077F4                                         ; 从堆栈中取出保存着的框架指针
.text:004077F4                                         ; [ebp+KTRAP_FRAME_EDX]
.text:004077F7                 mov     [ecx+134h], edx ; KThread->TrapFrame = KTRAP_FRAME->Edx 恢复ring3 陷阱帧.
.text:004077F7 _KiFastCallEntry endp ; sp-analysis failed
```

　　首先将堆栈指针恢复指向系统调用框架即自陷框架的底部，因为这些参数已经失去意义，然后把原先保存在堆栈上的先前自陷框架指针恢复到当前线程的控制块中。

 

## 0x05 KiServiceExit

　　然后继续执行KiServiceExit函数

```cpp
.text:004077FD _KiServiceExit  proc near               ; CODE XREF: _KiSetLowWaitHighThread+7Cj
.text:004077FD                                         ; NtContinue(x,x)+42j ...
.text:004077FD
.text:004077FD arg_C           = dword ptr  10h
.text:004077FD arg_10          = dword ptr  14h
.text:004077FD arg_40          = dword ptr  44h
.text:004077FD arg_44          = dword ptr  48h
.text:004077FD arg_48          = dword ptr  4Ch
.text:004077FD arg_60          = dword ptr  64h
.text:004077FD arg_64          = dword ptr  68h
.text:004077FD arg_68          = dword ptr  6Ch
.text:004077FD arg_6C          = dword ptr  70h
.text:004077FD
.text:004077FD ; FUNCTION CHUNK AT .text:00407908 SIZE 00000088 BYTES
.text:004077FD
.text:004077FD                 cli                     ; 关中断
.text:004077FE                 test    dword ptr [ebp+70h], 20000h ;  _KTRAP_FRAME->EFlags is this a V86 frame
.text:00407805                 jnz     short CHECK_FOR_APC_DELIVER ;  跳则不是V86
.text:00407807                 test    byte ptr [ebp+6Ch], 1 ; KTRAP_FRAME->SegCs 测试CS是否是R3选择子
.text:0040780B                 jz      short loc_407864 ; 如果CPL非0则跳.
.text:0040780D
.text:0040780D CHECK_FOR_APC_DELIVER:                  ; CODE XREF: _KiServiceExit+8j
.text:0040780D                                         ; _KiServiceExit+63j
.text:0040780D                 mov     ebx, ds:0FFDFF124h ; ebx->_KTHREAD
.text:00407813                 mov     byte ptr [ebx+2Eh], 0 ;  清除线程警觉位. APC有关.
.text:00407817                 cmp     byte ptr [ebx+4Ah], 0 ; 这里判断是否有APC挂起
.text:0040781B                 jz      short loc_407864 ; 没有APC挂起
.text:0040781B                                         ; 如果先前模式是内核模式，就往前跳转到下面，不递交APC请求
.text:0040781D                 mov     ebx, ebp
.text:0040781F                 mov     [ebx+44h], eax  ;  保存调用例程的返回值
.text:00407822                 mov     dword ptr [ebx+50h], 3Bh
.text:00407829                 mov     dword ptr [ebx+38h], 23h
.text:00407830                 mov     dword ptr [ebx+34h], 23h
.text:00407837                 mov     dword ptr [ebx+30h], 0
.text:0040783E                 mov     ecx, 1          ;  APC_LEVEL 将当前线程IRQL调整到APC_LEVEL
.text:00407843                 call    ds:__imp_@KfRaiseIrql@4 ; 这是快速调用模式的函数，通过寄存器传递参数
.text:00407849                 push    eax             ; 保存旧的IRQL.
.text:0040784A                 sti                     ;  开中断以后, 有可能带来线程切换
.text:0040784B                 push    ebx             ; _KTRAP_FRAME
.text:0040784C                 push    0               ; Null exception frame
.text:0040784E                 push    1               ; Previous mode = User Mode
.text:00407850                 call    _KiDeliverApc@12 ; 执行内核APC，并未用户空间APC的执行进行准备
.text:00407855                 pop     ecx             ; 从堆栈恢复老的运行级别
.text:00407856                 call    ds:__imp_@KfLowerIrql@4 ; 恢复原来的运行级别，在这里应该是PASSIVE_LEVEL
.text:0040785C                 mov     eax, [ebx+44h]  ;  重新读出Eax
.text:0040785F                 cli
.text:00407860                 jmp     short CHECK_FOR_APC_DELIVER ; 这是一个循环, 循环的处理APC
.text:00407860 ; ---------------------------------------------------------------------------
.text:00407862                 align 4
.text:00407864
.text:00407864 loc_407864:                             ; CODE XREF: _KiServiceExit+Ej
.text:00407864                                         ; _KiServiceExit+1Ej
.text:00407864                 mov     edx, [esp+arg_48] ; ExceptionList   arg_48 = 0x4C
.text:00407868                 mov     ebx, large fs:50h
.text:0040786F                 mov     large fs:0, edx ;  还原线程seh
.text:00407876                 mov     ecx, [esp+arg_44]
.text:0040787A                 mov     esi, large fs:124h ;  esi-->_KTHREAD
.text:00407881                 mov     [esi+140h], cl  ;  _KTHREAD.PreviousMode = _KTRAP_FRAME.PreviousPreviousMode
.text:00407887                 test    ebx, 0FFh       ; 当前线程是否在调试
.text:0040788D                 jnz     short loc_407908 ; 是被调试, 则跳走
.text:0040788F
.text:0040788F loc_40788F:                             ; CODE XREF: _KiServiceExit+11Bj
.text:0040788F                                         ; _KiServiceExit+14Aj
.text:0040788F                 test    [esp+arg_6C], 20000h ; 判断当前是否是V86模式.
.text:0040788F                                         ; arg_6c = 0x70
.text:00407897                 jnz     loc_408188      ; 是, 则跳走
.text:0040789D                 test    word ptr [esp+arg_68], 0FFF8h ; FRAME_EDITED
.text:004078A4                 jz      loc_40795E
.text:004078AA                 cmp     word ptr [esp+arg_68], 1Bh ;  set/clear ZF
.text:004078B0                 bt      word ptr [esp+arg_68], 0 ; test MODE_MASK      set/clear CF
.text:004078B7                 cmc
.text:004078B8                 ja      loc_40794C      ; jmp if CF=0 and ZF=0
.text:004078BE                 cmp     word ptr [ebp+6Ch], 8 ; _KTRAP_FRAME.Cs 选择子的合法性
.text:004078C3                 jz      short loc_4078CA ; 如果CS是内核模式, 那么我们直接就可以跳到恢复通用寄存器的地方
.text:004078C5
.text:004078C5 loc_4078C5:                             ; CODE XREF: _KiServiceExit+15Cj
.text:004078C5                 lea     esp, [ebp+50h]  ;  恢复FS
.text:004078C8                 pop     fs
.text:004078CA                 assume fs:nothing
.text:004078CA
.text:004078CA loc_4078CA:                             ; CODE XREF: _KiServiceExit+C6j
.text:004078CA                 lea     esp, [ebp+54h]  ; 获取edi的值
.text:004078CD                 pop     edi
.text:004078CE                 pop     esi
.text:004078CF                 pop     ebx
.text:004078D0                 pop     ebp
.text:004078D1                 cmp     word ptr [esp-60h+arg_64], 80h
.text:004078D8                 ja      loc_4081A4
.text:004078DE                 add     esp, 4
.text:004078E1                 test    [esp-64h+arg_64], 1 ; 是从用户空间发起的调用
.text:004078E1 _KiServiceExit  endp ; sp-analysis failed
.text:004078E1
.text:004078E9
.text:004078E9 ; =============== S U B R O U T I N E =======================================
.text:004078E9
.text:004078E9
.text:004078E9 _KiSystemCallExitBranch proc near       ; DATA XREF: KiEnableFastSyscallReturn():loc_439CBBr
.text:004078E9                                         ; KiEnableFastSyscallReturn()+26w ...
.text:004078E9                 jnz     short _KiSystemCallExit ; 测试是否是从内核种发起的调用
.text:004078EB                 pop     edx
.text:004078EC                 pop     ecx
.text:004078ED                 popf
.text:004078EE                 jmp     edx             ; 从内核中发起的调用, 在这里返回
.text:004078F0 ; ---------------------------------------------------------------------------
.text:004078F0
.text:004078F0 _KiSystemCallExit:                      ; CODE XREF: _KiSystemCallExitBranchj
.text:004078F0                                         ; _KiSystemCallExit2+5j
.text:004078F0                                         ; DATA XREF: ...
.text:004078F0                 iret
.text:004078F0 _KiSystemCallExitBranch endp ; sp-analysis failed
.text:004078F0
.text:004078F1
.text:004078F1 ; =============== S U B R O U T I N E =======================================
.text:004078F1
.text:004078F1
.text:004078F1 _KiSystemCallExit2 proc near            ; DATA XREF: KiRestoreFastSyscallReturnState()+16o
.text:004078F1
.text:004078F1 arg_5           = byte ptr  9
.text:004078F1
.text:004078F1                 test    [esp+arg_5], 1
.text:004078F6                 jnz     short _KiSystemCallExit ;  不为0是则是通过自陷指令进入内核的
.text:004078F8                 pop     edx             ; New R3 EIP
.text:004078F9                 add     esp, 4          ;  Skip R3 DS
.text:004078FC                 and     [esp-8+arg_5], 0FDh ; NOT EFLAGS_INTERRUPT_MASK ; 关闭中断标记位
.text:00407901                 popf                    ; 还原eflag
.text:00407902                 pop     ecx             ;  ecx = _KTRAP_FRAME.esp  r3 的栈顶
.text:00407903                 sti                     ; 开中断
.text:00407904                 sysexit                 ; 退出内核模式.
.text:00407906                 iret
.text:00407906 _KiSystemCallExit2 endp ; sp-analysis failed
```

在KiServiceExit执行的时候，首先关闭中断，然后检查是否有APC请求，如果有就通过KiDeliverApc递交APC请求(插入线程apc队列)。

最后会通过TrapFrame返回r3或者返回内核调用Zw函数的地方。

 

## 0x06 NtProtectVirtualMemory

　我们再看看call ebx之后调用Nt函数的情况，NtProtectVirtualMemory代码如下：

```cpp
PAGE:0049ACB1 ; NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect)
PAGE:0049ACB1 _NtProtectVirtualMemory@20 proc near    ; DATA XREF: .text:0040B8CCo
PAGE:0049ACB1
PAGE:0049ACB1 var_54          = dword ptr -54h
PAGE:0049ACB1 Status          = dword ptr -3Ch
PAGE:0049ACB1 LastProtect     = dword ptr -38h
PAGE:0049ACB1 CurrentProcess  = dword ptr -34h
PAGE:0049ACB1 var_30          = dword ptr -30h
PAGE:0049ACB1 AccessMode      = byte ptr -2Ch
PAGE:0049ACB1 Attached        = dword ptr -28h
PAGE:0049ACB1 CapturedBase    = dword ptr -24h
PAGE:0049ACB1 CapturedRegionSize= dword ptr -20h
PAGE:0049ACB1 Object          = dword ptr -1Ch
PAGE:0049ACB1 ms_exc          = CPPEH_RECORD ptr -18h
PAGE:0049ACB1 ProcessHandle   = dword ptr  8
PAGE:0049ACB1 BaseAddress     = dword ptr  0Ch
PAGE:0049ACB1 ProtectSize     = dword ptr  10h
PAGE:0049ACB1 NewProtect      = dword ptr  14h
PAGE:0049ACB1 OldProtect      = dword ptr  18h
PAGE:0049ACB1
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:004B9A0D SIZE 00000024 BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:004E7866 SIZE 00000018 BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:0051C445 SIZE 00000023 BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:0051C46D SIZE 0000000E BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:0051C480 SIZE 00000044 BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:0051C4C9 SIZE 00000004 BYTES
PAGE:0049ACB1 ; FUNCTION CHUNK AT PAGE:0051C4D2 SIZE 00000008 BYTES
PAGE:0049ACB1
PAGE:0049ACB1                 push    44h
PAGE:0049ACB3                 push    offset stru_413468
PAGE:0049ACB8                 call    __SEH_prolog
PAGE:0049ACBD                 xor     ebx, ebx
PAGE:0049ACBF                 mov     [ebp+Attached], ebx
PAGE:0049ACC2                 mov     ecx, [ebp+NewProtect] ; NewProtect
PAGE:0049ACC5                 call    @MiMakeProtectionMask@4 ; ProtectionMask = MiMakeProtectionMask (NewProtect);
PAGE:0049ACCA                 cmp     eax, 0FFFFFFFFh ; MM_INVALID_PROTECTION
PAGE:0049ACCD                 jz      loc_51C445      ; STATUS_INVALID_PAGE_PROTECTION
PAGE:0049ACD3                 mov     eax, large fs:124h ; PsGetCurrentThread()
PAGE:0049ACD9                 mov     ecx, [eax+44h]  ; EHTREAD中的Process指针
PAGE:0049ACDC                 mov     [ebp+CurrentProcess], ecx ; PsGetCurrentProcessByThread (CurrentThread)
PAGE:0049ACDF                 mov     al, [eax+140h]  ; PreviousMode
PAGE:0049ACE5                 mov     [ebp+AccessMode], al
PAGE:0049ACE8                 test    al, al
PAGE:0049ACEA                 jz      loc_4E7866      ; PreviousMode = 0(jz为0 跳转)
PAGE:0049ACEA                                         ; 用户层调用则不跳转
PAGE:0049ACF0                 mov     [ebp+ms_exc.registration.TryLevel], ebx
PAGE:0049ACF3                 mov     edi, [ebp+BaseAddress]
PAGE:0049ACF6                 mov     eax, _MmUserProbeAddress     ;ProbeForWritePointer (BaseAddress);
PAGE:0049ACFB                 cmp     edi, eax
PAGE:0049ACFD                 jnb     loc_51C44F
PAGE:0049AD03
PAGE:0049AD03 loc_49AD03:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817A0j
PAGE:0049AD03                 mov     eax, [edi]
PAGE:0049AD05                 mov     [edi], eax
PAGE:0049AD07                 mov     esi, [ebp+ProtectSize]
PAGE:0049AD0A                 mov     eax, _MmUserProbeAddress    ;ProbeForWriteUlong_ptr (RegionSize);
PAGE:0049AD0F                 cmp     esi, eax
PAGE:0049AD11                 jnb     loc_51C456
PAGE:0049AD17
PAGE:0049AD17 loc_49AD17:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817A7j
PAGE:0049AD17                 mov     eax, [esi]
PAGE:0049AD19                 mov     [esi], eax
PAGE:0049AD1B                 mov     ebx, [ebp+OldProtect]
PAGE:0049AD1E                 mov     eax, _MmUserProbeAddress        ;ProbeForWriteUlong (OldProtect);
PAGE:0049AD23                 cmp     ebx, eax
PAGE:0049AD25                 jnb     loc_51C45D
PAGE:0049AD2B
PAGE:0049AD2B loc_49AD2B:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817B2j
PAGE:0049AD2B                 mov     eax, [ebx]
PAGE:0049AD2D                 mov     [ebx], eax
PAGE:0049AD2F                 mov     ecx, [edi]
PAGE:0049AD31                 mov     [ebp+CapturedBase], ecx        ;CapturedBase = *BaseAddress;
PAGE:0049AD34                 mov     edx, [esi]
PAGE:0049AD36                 mov     [ebp+CapturedRegionSize], edx        ;CapturedRegionSize = *RegionSize;
PAGE:0049AD39                 or      [ebp+ms_exc.registration.TryLevel], 0FFFFFFFFh
PAGE:0049AD3D
PAGE:0049AD3D loc_49AD3D:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+4CBC8j
PAGE:0049AD3D                 mov     eax, _MmHighestUserAddress
PAGE:0049AD42                 cmp     ecx, eax        ; CapturedBase>MM_HIGHEST_USER_ADDRESS
PAGE:0049AD44                 ja      RETURN_STATUS_INVALID_PARAMETER_2 ; 跳转无效的参数
PAGE:0049AD4A                 sub     eax, ecx        ; MM_HIGHEST_USER_ADDRESS-CapturedBase
PAGE:0049AD4C                 cmp     eax, edx        ; >CapturedRegionSize
PAGE:0049AD4E                 jb      RETURN_STATUS_INVALID_PARAMETER_3 ; 跳转无效的参数
PAGE:0049AD54                 test    edx, edx        ; edx=0
PAGE:0049AD56                 jz      RETURN_STATUS_INVALID_PARAMETER_3 ; 跳转无效的参数
PAGE:0049AD5C                 push    0               ; HandleInformation
PAGE:0049AD5E                 lea     eax, [ebp+Object]
PAGE:0049AD61                 push    eax             ; Object
PAGE:0049AD62                 push    dword ptr [ebp+AccessMode] ; AccessMode
PAGE:0049AD65                 push    _PsProcessType  ; ObjectType
PAGE:0049AD6B                 push    8               ; DesiredAccess   PROCESS_VM_OPERATION
PAGE:0049AD6D                 push    [ebp+ProcessHandle] ; Handle
PAGE:0049AD70                 call    _ObReferenceObjectByHandle@24 ; ObReferenceObjectByHandle(x,x,x,x,x,x)
PAGE:0049AD75                 test    eax, eax
PAGE:0049AD77                 jl      loc_49AE0B      ; 返回0则跳走
PAGE:0049AD7D                 mov     eax, [ebp+Object]
PAGE:0049AD80                 cmp     [ebp+CurrentProcess], eax ; 比较ObRef..得到的Process是否等于CurrentProcess
PAGE:0049AD83                 jnz     loc_4B9A1B      ; 不等于，调用KeStackAttachProcess附加到进程空间
PAGE:0049AD89
PAGE:0049AD89 loc_49AD89:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+1ED7Bj
PAGE:0049AD89                 lea     eax, [ebp+LastProtect]
PAGE:0049AD8C                 push    eax             ; &LastProtect
PAGE:0049AD8D                 push    [ebp+NewProtect] ; NewProtect
PAGE:0049AD90                 lea     eax, [ebp+CapturedRegionSize]
PAGE:0049AD93                 push    eax             ; &CapturedRegionSize
PAGE:0049AD94                 lea     eax, [ebp+CapturedBase]
PAGE:0049AD97                 push    eax             ; &CapturedBase
PAGE:0049AD98                 push    [ebp+Object]    ; Process
PAGE:0049AD9B                 call    _MiProtectVirtualMemory@20 ; MiProtectVirtualMemory(x,x,x,x,x)
PAGE:0049ADA0                 mov     [ebp+Status], eax
PAGE:0049ADA3                 cmp     [ebp+Attached], 0 ; 是否附加了，之前KeStackDetachProcess调用的时候修改的
PAGE:0049ADA7                 jnz     loc_4B9A0D      ; 调用KeUnStackDetachProcess
PAGE:0049ADAD
PAGE:0049ADAD loc_49ADAD:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+1ED65j
PAGE:0049ADAD                 mov     ecx, [ebp+Object] ; Object
PAGE:0049ADB0                 call    @ObfDereferenceObject@4 ; ObfDereferenceObject(x)
PAGE:0049ADB5                 mov     [ebp+ms_exc.registration.TryLevel], 1
PAGE:0049ADBC                 cmp     [ebp+AccessMode], 0
PAGE:0049ADC0                 jz      short loc_49ADF5 ; 内核模式跳转
PAGE:0049ADC0                                         ; *RegionSize = CapturedRegionSize;
PAGE:0049ADC0                                         ; *BaseAddress = CapturedBase;
PAGE:0049ADC0                                         ; *OldProtect = LastProtect;
PAGE:0049ADC2                 mov     eax, _MmUserProbeAddress
PAGE:0049ADC7                 cmp     edi, eax
PAGE:0049ADC9                 jnb     loc_51C4A3
PAGE:0049ADCF
PAGE:0049ADCF loc_49ADCF:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817F8j
PAGE:0049ADCF                 mov     eax, [edi]
PAGE:0049ADD1                 mov     [edi], eax
PAGE:0049ADD3                 mov     eax, _MmUserProbeAddress
PAGE:0049ADD8                 cmp     esi, eax
PAGE:0049ADDA                 jnb     loc_51C4AE
PAGE:0049ADE0
PAGE:0049ADE0 loc_49ADE0:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+81803j
PAGE:0049ADE0                 mov     eax, [esi]
PAGE:0049ADE2                 mov     [esi], eax
PAGE:0049ADE4                 mov     eax, _MmUserProbeAddress
PAGE:0049ADE9                 cmp     ebx, eax
PAGE:0049ADEB                 jnb     loc_51C4B9
PAGE:0049ADF1
PAGE:0049ADF1 loc_49ADF1:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+8180Ej
PAGE:0049ADF1                 mov     eax, [ebx]
PAGE:0049ADF3                 mov     [ebx], eax
PAGE:0049ADF5
PAGE:0049ADF5 loc_49ADF5:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+10Fj
PAGE:0049ADF5                 mov     eax, [ebp+CapturedRegionSize]
PAGE:0049ADF8                 mov     [esi], eax
PAGE:0049ADFA                 mov     eax, [ebp+CapturedBase]
PAGE:0049ADFD                 mov     [edi], eax
PAGE:0049ADFF                 mov     eax, [ebp+LastProtect]
PAGE:0049AE02                 mov     [ebx], eax
PAGE:0049AE04
PAGE:0049AE04 loc_49AE04:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+81824j
PAGE:0049AE04                 or      [ebp+ms_exc.registration.TryLevel], 0FFFFFFFFh
PAGE:0049AE08                 mov     eax, [ebp+Status]
PAGE:0049AE0B
PAGE:0049AE0B loc_49AE0B:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+C6j
PAGE:0049AE0B                                         ; NtProtectVirtualMemory(x,x,x,x,x)+81799j ...
PAGE:0049AE0B                 call    __SEH_epilog
PAGE:0049AE10                 retn    14h
PAGE:0049AE10 _NtProtectVirtualMemory@20 endp
```

　　我们看到中间有个地方对于PreviousMode有一个判断，如果PreviousMode为用户模式则不跳转，为内核模式则跳转，我们看看跳转的代码：

```cpp
PAGE:0049ACEA                 jz      loc_4E7866      ; PreviousMode = 0(jz为0 跳转)
PAGE:0049ACEA                                         ; 用户层调用则不跳转
```

```cpp
PAGE:004E7866 loc_4E7866:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+39j
PAGE:004E7866                 mov     esi, [ebp+ProtectSize]
PAGE:004E7869                 mov     edx, [esi]
PAGE:004E786B                 mov     [ebp+CapturedRegionSize], edx
PAGE:004E786E                 mov     edi, [ebp+BaseAddress]
PAGE:004E7871                 mov     ecx, [edi]
PAGE:004E7873                 mov     [ebp+CapturedBase], ecx
PAGE:004E7876                 mov     ebx, [ebp+OldProtect]
PAGE:004E7879                 jmp     loc_49AD3D
```

```cpp
PAGE:0049AD3D loc_49AD3D:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+4CBC8j
PAGE:0049AD3D                 mov     eax, _MmHighestUserAddress
PAGE:0049AD42                 cmp     ecx, eax        ; CapturedBase>MM_HIGHEST_USER_ADDRESS
PAGE:0049AD44                 ja      RETURN_STATUS_INVALID_PARAMETER_2 ; 跳转无效的参数
PAGE:0049AD4A                 sub     eax, ecx        ; MM_HIGHEST_USER_ADDRESS-CapturedBase
PAGE:0049AD4C                 cmp     eax, edx        ; >CapturedRegionSize
PAGE:0049AD4E                 jb      RETURN_STATUS_INVALID_PARAMETER_3 ; 跳转无效的参数
PAGE:0049AD54                 test    edx, edx        ; edx=0
PAGE:0049AD56                 jz      RETURN_STATUS_INVALID_PARAMETER_3 ; 跳转无效的参数
PAGE:0049AD5C                 push    0               ; HandleInformation
PAGE:0049AD5E                 lea     eax, [ebp+Object]
PAGE:0049AD61                 push    eax             ; Object
PAGE:0049AD62                 push    dword ptr [ebp+AccessMode] ; AccessMode
PAGE:0049AD65                 push    _PsProcessType  ; ObjectType
PAGE:0049AD6B                 push    8               ; DesiredAccess   PROCESS_VM_OPERATION
PAGE:0049AD6D                 push    [ebp+ProcessHandle] ; Handle
PAGE:0049AD70                 call    _ObReferenceObjectByHandle@24 ; ObReferenceObjectByHandle(x,x,x,x,x,x)
```

　　可以看到如果是内核模式，直接跳过了校验参数合法性的部分，直接走入下面的ObRegerenceObjectByHandle,跳过的代码如下所示：

```cpp
PAGE:0049ACF0                 mov     [ebp+ms_exc.registration.TryLevel], ebx
PAGE:0049ACF3                 mov     edi, [ebp+BaseAddress]
PAGE:0049ACF6                 mov     eax, _MmUserProbeAddress     ;ProbeForWritePointer (BaseAddress);
PAGE:0049ACFB                 cmp     edi, eax
PAGE:0049ACFD                 jnb     loc_51C44F
PAGE:0049AD03
PAGE:0049AD03 loc_49AD03:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817A0j
PAGE:0049AD03                 mov     eax, [edi]
PAGE:0049AD05                 mov     [edi], eax
PAGE:0049AD07                 mov     esi, [ebp+ProtectSize]
PAGE:0049AD0A                 mov     eax, _MmUserProbeAddress    ;ProbeForWriteUlong_ptr (RegionSize);
PAGE:0049AD0F                 cmp     esi, eax
PAGE:0049AD11                 jnb     loc_51C456
PAGE:0049AD17
PAGE:0049AD17 loc_49AD17:                             ; CODE XREF: NtProtectVirtualMemory(x,x,x,x,x)+817A7j
PAGE:0049AD17                 mov     eax, [esi]
PAGE:0049AD19                 mov     [esi], eax
PAGE:0049AD1B                 mov     ebx, [ebp+OldProtect]
PAGE:0049AD1E                 mov     eax, _MmUserProbeAddress        ;ProbeForWriteUlong (OldProtect);
PAGE:0049AD23                 cmp     ebx, eax
PAGE:0049AD25                 jnb     loc_51C45D
```

　　所以我们可以看出PreviousMode为内核模式的时候会比用户模式检查的地方少，效率会快一些。

## 0x07 x64位下的内核Zw调用Nt函数

```cpp
.text:00000001400795E0                ZwProtectVirtualMemory proc near        ; CODE XREF: KiOpPatchCode+C9p
.text:00000001400795E0                                                        ; KiOpPatchCode+1E2p ...
.text:00000001400795E0 48 8B C4                       mov     rax, rsp
.text:00000001400795E3 FA                             cli                     ; 关中断
.text:00000001400795E4 48 83 EC 10                    sub     rsp, 10h        ; 开辟栈区
.text:00000001400795E8 50                             push    rax             ; 保存栈顶
.text:00000001400795E9 9C                             pushfq                  ; ELFALGS
.text:00000001400795EA 6A 10                          push    10h
.text:00000001400795EC 48 8D 05 7D 28+                lea     rax, KiServiceLinkage
.text:00000001400795F3 50                             push    rax
.text:00000001400795F4 B8 4D 00 00 00                 mov     eax, 4Dh        ; 函数索引0x4D
.text:00000001400795F9 E9 C2 5F 00 00                 jmp     KiServiceInternal
.text:00000001400795F9                ZwProtectVirtualMemory endp
```

```cpp
.text:000000014007F5C0                KiServiceInternal proc near             ; CODE XREF: ZwMapUserPhysicalPagesScatter+19j
.text:000000014007F5C0                                                        ; ZwWaitForSingleObject+19j ...
.text:000000014007F5C0
.text:000000014007F5C0                var_140         = byte ptr -140h
.text:000000014007F5C0                var_30          = qword ptr -30h
.text:000000014007F5C0                var_28          = qword ptr -28h
.text:000000014007F5C0                var_20          = qword ptr -20h
.text:000000014007F5C0                var_18          = qword ptr -18h
.text:000000014007F5C0
.text:000000014007F5C0 48 83 EC 08                    sub     rsp, 8
.text:000000014007F5C4 55                             push    rbp
.text:000000014007F5C5 48 81 EC 58 01+                sub     rsp, 158h       ; 栈区
.text:000000014007F5CC 48 8D AC 24 80+                lea     rbp, [rsp+80h]  ; 栈底
.text:000000014007F5D4 48 89 9D C0 00+                mov     [rbp+0E8h+var_28], rbx ; mov     TrRbx[rbp], rbx
.text:000000014007F5DB 48 89 BD C8 00+                mov     [rbp+0E8h+var_20], rdi ; mov     TrRdi[rbp], rdi
.text:000000014007F5E2 48 89 B5 D0 00+                mov     [rbp+0E8h+var_18], rsi ; mov     TrRsi[rbp], rsi
.text:000000014007F5E9 FB                             sti                     ; 开中断
.text:000000014007F5EA 65 48 8B 1C 25+                mov     rbx, gs:188h    ; PcCurrentThread  get current thread address
.text:000000014007F5F3 0F 0D 8B D8 01+                prefetchw byte ptr [rbx+1D8h] ; prefetch with write intent
.text:000000014007F5FA 0F B6 BB F6 01+                movzx   edi, byte ptr [rbx+1F6h] ; save previous mode in trap frame
.text:000000014007F601 40 88 7D A8                    mov     [rbp+0E8h+var_140], dil
.text:000000014007F605 C6 83 F6 01 00+                mov     byte ptr [rbx+1F6h], 0 ; set thread previous mode
.text:000000014007F60C 4C 8B 93 D8 01+                mov     r10, [rbx+1D8h] ; save previous frame pointer address
.text:000000014007F613 4C 89 95 B8 00+                mov     [rbp+0E8h+var_30], r10
.text:000000014007F61A 4C 8D 1D 3D 01+                lea     r11, KiSystemServiceStart ;  get address of service start
.text:000000014007F621 41 FF E3                       jmp     r11             ;  finish in common code
.text:000000014007F621                KiServiceInternal endp
```

　　ZwProtectVirtualMemory调用了KiServiceLinkage，把系统服务序号放进eax后又调用了KiServiceInternal，KiServiceInternal又调用了KiSystemServiceStart。KiServiceLinkage和KiServiceInternal是初始化系统服务的，KiSystemServiceStart则是开始执行系统服务。我们再看看KiSystemServiceStart干了些什么：

```cpp
.text:000000014007F640                KiSystemCall64  proc near               ; DATA XREF: KiInitializeBootStructures+26Eo
.text:000000014007F640
...
.text:000000014007F75E                KiSystemServiceStart:                   ; DATA XREF: KiServiceInternal+5Ao
.text:000000014007F75E                                                        ; .data:00000001401EE648o
.text:000000014007F75E 48 89 A3 D8 01+                mov     [rbx+1D8h], rsp ; ThTrapFrame[rbx]  set current frame pointer address
.text:000000014007F765 8B F8                          mov     edi, eax
.text:000000014007F767 C1 EF 07                       shr     edi, 7          ; SERVICE_TABLE_SHIFT
.text:000000014007F76A 83 E7 20                       and     edi, 20h        ; SERVICE_TABLE_MASK
.text:000000014007F76D 25 FF 0F 00 00                 and     eax, 0FFFh      ; SERVICE_NUMBER_MASK
.text:000000014007F772
.text:000000014007F772                KiSystemServiceRepeat:                  ; CODE XREF: KiSystemCall64+47Bj
.text:000000014007F772 4C 8D 15 C7 20+                lea     r10, KeServiceDescriptorTable ; get table base address
.text:000000014007F779 4C 8D 1D 00 21+                lea     r11, KeServiceDescriptorTableShadow
.text:000000014007F780 F7 83 00 01 00+                test    dword ptr [rbx+100h], 80h
.text:000000014007F78A 4D 0F 45 D3                    cmovnz  r10, r11
.text:000000014007F78E 42 3B 44 17 10                 cmp     eax, [rdi+r10+10h]
.text:000000014007F793 0F 83 E9 02 00+                jnb     loc_14007FA82
.text:000000014007F799 4E 8B 14 17                    mov     r10, [rdi+r10]
.text:000000014007F79D 4D 63 1C 82                    movsxd  r11, dword ptr [r10+rax*4] ; get system service offset
.text:000000014007F7A1 49 8B C3                       mov     rax, r11
.text:000000014007F7A4 49 C1 FB 04                    sar     r11, 4
.text:000000014007F7A8 4D 03 D3                       add     r10, r11        ; add table base to
.text:000000014007F7AB 83 FF 20                       cmp     edi, 20h        ; check if GUI service
.text:000000014007F7AE 75 50                          jnz     short loc_14007F800 ; if ne,not GUI service
.text:000000014007F7B0 4C 8B 9B B8 00+                mov     r11, [rbx+0B8h] ; get user TEB address
.text:000000014007F7B7
.text:000000014007F7B7                KiSystemServiceGdiTebAccess:            ; DATA XREF: KiSystemServiceHandler+Do
.text:000000014007F7B7 41 83 BB 40 17+                cmp     dword ptr [r11+1740h], 0 ; check batch queue depth
.text:000000014007F7BF 74 3F                          jz      short loc_14007F800 ; if e,batch queue empty
.text:000000014007F7C1 48 89 45 B0                    mov     [rbp-50h], rax
.text:000000014007F7C5 48 89 4D B8                    mov     [rbp-48h], rcx  ; mov TrRcx[rbp],rcx    save system service arguments
.text:000000014007F7C9 48 89 55 C0                    mov     [rbp-40h], rdx
.text:000000014007F7CD 49 8B D8                       mov     rbx, r8
.text:000000014007F7D0 49 8B F9                       mov     rdi, r9
.text:000000014007F7D3 49 8B F2                       mov     rsi, r10        ; save system service address
.text:000000014007F7D6 FF 15 34 1F 23+                call    cs:KeGdiFlushUserBatch ; call flush GDI user batch routine
.text:000000014007F7DC 48 8B 45 B0                    mov     rax, [rbp-50h]  ; restore system service arguments
.text:000000014007F7E0 48 8B 4D B8                    mov     rcx, [rbp-48h]
.text:000000014007F7E4 48 8B 55 C0                    mov     rdx, [rbp-40h]
.text:000000014007F7E8 4C 8B C3                       mov     r8, rbx
.text:000000014007F7EB 4C 8B CF                       mov     r9, rdi
.text:000000014007F7EE 4C 8B D6                       mov     r10, rsi        ; restore system service address
.text:000000014007F7F1                                db      66h, 66h, 66h, 66h, 66h, 66h
.text:000000014007F7F1 66 66 66 66 66+                nop     word ptr [rax+rax+00000000h]
.text:000000014007F800
.text:000000014007F800                loc_14007F800:                          ; CODE XREF: KiSystemCall64+16Ej
.text:000000014007F800                                                        ; KiSystemCall64+17Fj
.text:000000014007F800 83 E0 0F                       and     eax, 0Fh        ; ; Check if system service has any in memory arguments.
.text:000000014007F803 0F 84 B7 00 00+                jz      KiSystemServiceCopyEnd ; if z, no in memory arguments
.text:000000014007F809 C1 E0 03                       shl     eax, 3          ; compute argument bytes for dispatch
.text:000000014007F80C 48 8D 64 24 90                 lea     rsp, [rsp-70h]  ; allocate stack argument area
.text:000000014007F811 48 8D 7C 24 18                 lea     rdi, [rsp+190h+var_178] ; compute copy destination address
.text:000000014007F816 48 8B B5 00 01+                mov     rsi, [rbp+100h] ;  get previous stack address  TrRsp[rbp]
.text:000000014007F81D 48 8D 76 20                    lea     rsi, [rsi+20h]  ; compute copy source address
.text:000000014007F821 F6 85 F0 00 00+                test    byte ptr [rbp+0F0h], 1 ; check if previous mode user   TrSegCs[rbp]
.text:000000014007F828 74 16                          jz      short loc_14007F840 ; if z, previous mode kernel
.text:000000014007F82A 48 3B 35 CF 17+                cmp     rsi, cs:MmUserProbeAddress ; check if source address in range
.text:000000014007F831 48 0F 43 35 C7+                cmovnb  rsi, cs:MmUserProbeAddress ; if ae, reset copy source address
.text:000000014007F839 0F 1F 80 00 00+                nop     dword ptr [rax+00000000h]
.text:000000014007F840
.text:000000014007F840                loc_14007F840:                          ; CODE XREF: KiSystemCall64+1E8j
.text:000000014007F840 4C 8D 1D 79 00+                lea     r11, KiSystemServiceCopyEnd ; get copy ending address
.text:000000014007F847 4C 2B D8                       sub     r11, rax        ; substract number of bytes to copy
.text:000000014007F84A 41 FF E3                       jmp     r11
.text:000000014007F84A                ; ---------------------------------------------------------------------------
.text:000000014007F84D 0F 1F 00                       align 10h
.text:000000014007F850
.text:000000014007F850                KiSystemServiceCopyStart:               ; DATA XREF: KiSystemServiceHandler+1Ao
.text:000000014007F850 48 8B 46 70                    mov     rax, [rsi+70h]  ; copy fourteenth argument
.text:000000014007F854 48 89 47 70                    mov     [rdi+70h], rax
.text:000000014007F858 48 8B 46 68                    mov     rax, [rsi+68h]  ; copy thirteenth argument
.text:000000014007F85C 48 89 47 68                    mov     [rdi+68h], rax
.text:000000014007F860 48 8B 46 60                    mov     rax, [rsi+60h]  ; copy twelfth argument
.text:000000014007F864 48 89 47 60                    mov     [rdi+60h], rax
.text:000000014007F868 48 8B 46 58                    mov     rax, [rsi+58h]  ; copy eleventh argument
.text:000000014007F86C 48 89 47 58                    mov     [rdi+58h], rax
.text:000000014007F870 48 8B 46 50                    mov     rax, [rsi+50h]  ; copy tenth argument
.text:000000014007F874 48 89 47 50                    mov     [rdi+50h], rax
.text:000000014007F878 48 8B 46 48                    mov     rax, [rsi+48h]  ; copy nineth argument
.text:000000014007F87C 48 89 47 48                    mov     [rdi+48h], rax
.text:000000014007F880 48 8B 46 40                    mov     rax, [rsi+40h]  ; copy eighth argument
.text:000000014007F884 48 89 47 40                    mov     [rdi+40h], rax
.text:000000014007F888 48 8B 46 38                    mov     rax, [rsi+38h]  ; copy seventh argument
.text:000000014007F88C 48 89 47 38                    mov     [rdi+38h], rax
.text:000000014007F890 48 8B 46 30                    mov     rax, [rsi+30h]  ; copy sixth argument
.text:000000014007F894 48 89 47 30                    mov     [rdi+30h], rax
.text:000000014007F898 48 8B 46 28                    mov     rax, [rsi+28h]  ; copy fifth argument
.text:000000014007F89C 48 89 47 28                    mov     [rdi+28h], rax
.text:000000014007F8A0 48 8B 46 20                    mov     rax, [rsi+20h]  ; copy fourth argument
.text:000000014007F8A4 48 89 47 20                    mov     [rdi+20h], rax
.text:000000014007F8A8 48 8B 46 18                    mov     rax, [rsi+18h]  ; copy third argument
.text:000000014007F8AC 48 89 47 18                    mov     [rdi+18h], rax
.text:000000014007F8B0 48 8B 46 10                    mov     rax, [rsi+10h]  ; copy second argument
.text:000000014007F8B4 48 89 47 10                    mov     [rdi+10h], rax
.text:000000014007F8B8 48 8B 46 08                    mov     rax, [rsi+8]    ; copy first argument
.text:000000014007F8BC 48 89 47 08                    mov     [rdi+8], rax
.text:000000014007F8C0
.text:000000014007F8C0                KiSystemServiceCopyEnd:                 ; CODE XREF: KiSystemCall64+1C3j
.text:000000014007F8C0                                                        ; DATA XREF: KiSystemServiceHandler+27o ...
.text:000000014007F8C0 F7 05 BE 7D 18+                test    cs:dword_140207688, 40h
.text:000000014007F8CA 0F 85 50 02 00+                jnz     loc_14007FB20
.text:000000014007F8D0 41 FF D2                       call    r10             ; call system service
.text:000000014007F8D3
.text:000000014007F8D3                loc_14007F8D3:                          ; CODE XREF: KiSystemCall64+535j
.text:000000014007F8D3 65 FF 04 25 38+                inc     dword ptr gs:2238h ; increment number of system calls  gs:[PcSystemCalls]
.text:000000014007F8DB
.text:000000014007F8DB                KiSystemServiceExit:                    ; CODE XREF: KiSystemCall64+49Cj
...
.text:000000014007FB75                KiSystemCall64  endp 
```

　　KiSystemServiceStart调用了KiSystemServiceRepeat，KiSystemServiceRepeat根据系统服务序号来选择SSDT还是ShadowSSDT(到了KiSystemServiceRepeat才真正调用Nt函数，通过call r11调用了Nt函数)。KiSystemServiceRepeat执行完成之后，会调用KiSystemServiceExit(系统服务调用完毕，会有返回信息)

　　我们接下来再看看NtProtectVirtualMemory函数的实现

```cpp
PAGE:0000000140398B2C                NtProtectVirtualMemory proc near        ; DATA XREF: .text:0000000140081568o
PAGE:0000000140398B2C
PAGE:0000000140398B2C                var_78          = qword ptr -78h
PAGE:0000000140398B2C                var_70          = qword ptr -70h
PAGE:0000000140398B2C                var_68          = qword ptr -68h
PAGE:0000000140398B2C                LastProtect     = dword ptr -58h
PAGE:0000000140398B2C                var_54          = dword ptr -54h
PAGE:0000000140398B2C                Object          = qword ptr -50h
PAGE:0000000140398B2C                CaptureRegionSize= qword ptr -48h
PAGE:0000000140398B2C                CapturedBase    = qword ptr -40h
PAGE:0000000140398B2C                ApcState        = byte ptr -38h
PAGE:0000000140398B2C                var_8           = byte ptr -8
PAGE:0000000140398B2C                OldProtect      = qword ptr  28h
PAGE:0000000140398B2C
PAGE:0000000140398B2C                ; FUNCTION CHUNK AT PAGE:00000001403C8D10 SIZE 0000001E BYTES
PAGE:0000000140398B2C
PAGE:0000000140398B2C 48 8B C4                       mov     rax, rsp
PAGE:0000000140398B2F 48 89 70 08                    mov     [rax+8], rsi
PAGE:0000000140398B33 48 89 78 10                    mov     [rax+10h], rdi
PAGE:0000000140398B37 4C 89 60 18                    mov     [rax+18h], r12
PAGE:0000000140398B3B 4C 89 68 20                    mov     [rax+20h], r13
PAGE:0000000140398B3F 41 56                          push    r14
PAGE:0000000140398B41 48 81 EC 90 00+                sub     rsp, 90h
PAGE:0000000140398B48 41 8B F9                       mov     edi, r9d        ; NewProtect
PAGE:0000000140398B4B 4D 8B E8                       mov     r13, r8         ; RegionSize
PAGE:0000000140398B4E 4C 8B E2                       mov     r12, rdx        ; *BaseAddress
PAGE:0000000140398B51 4C 8B D1                       mov     r10, rcx        ; ProcessHandle
PAGE:0000000140398B54 41 8B C9                       mov     ecx, r9d
PAGE:0000000140398B57 E8 A4 AE CF FF                 call    MiMakeProtectionMask ; MiMakeProtectionMask (NewProtect);
PAGE:0000000140398B5C 83 F8 FF                       cmp     eax, 0FFFFFFFFh
PAGE:0000000140398B5F 0F 84 AB 01 03+                jz      loc_1403C8D10   ; error
PAGE:0000000140398B65 65 48 8B 04 25+                mov     rax, gs:188h    ; 获得线程体
PAGE:0000000140398B6E 48 8B 70 70                    mov     rsi, [rax+70h]  ; 线程所属的Process
PAGE:0000000140398B72 44 8A 88 F6 01+                mov     r9b, [rax+1F6h] ; PreviousMode
PAGE:0000000140398B79 45 84 C9                       test    r9b, r9b
PAGE:0000000140398B7C 0F 84 3E 01 00+                jz      loc_140398CC0   ; 如果是KernelMode就跳转
PAGE:0000000140398B7C 00                                                     ; 如果是UserMode就继续执行
PAGE:0000000140398B82 49 8B CC                       mov     rcx, r12        ; BaseAddress
PAGE:0000000140398B85 48 8B 05 74 84+                mov     rax, cs:MmUserProbeAddress ; ProbeForWrite (BaseAddress, sizeof(PVOID64), sizeof(PVOID64));
PAGE:0000000140398B8C 4C 3B E0                       cmp     r12, rax
PAGE:0000000140398B8F 48 0F 43 C8                    cmovnb  rcx, rax        ; 大于等于时传送
PAGE:0000000140398B93 48 8B 01                       mov     rax, [rcx]
PAGE:0000000140398B96 48 89 01                       mov     [rcx], rax
PAGE:0000000140398B99 49 8B C8                       mov     rcx, r8         ; RegionSize
PAGE:0000000140398B9C 48 8B 05 5D 84+                mov     rax, cs:MmUserProbeAddress ; ProbeForWrite (RegionSize, sizeof(ULONGLONG), sizeof(ULONGLONG));
PAGE:0000000140398BA3 4C 3B C0                       cmp     r8, rax
PAGE:0000000140398BA6 48 0F 43 C8                    cmovnb  rcx, rax        ; 大于等于时传送
PAGE:0000000140398BAA 48 8B 01                       mov     rax, [rcx]
PAGE:0000000140398BAD 48 89 01                       mov     [rcx], rax
PAGE:0000000140398BB0 4C 8B B4 24 C0+                mov     r14, [rsp+98h+OldProtect]
PAGE:0000000140398BB8 49 8B CE                       mov     rcx, r14
PAGE:0000000140398BBB 48 8B 05 3E 84+                mov     rax, cs:MmUserProbeAddress ; ProbeForWriteUlong (OldProtect);
PAGE:0000000140398BC2 4C 3B F0                       cmp     r14, rax
PAGE:0000000140398BC5 48 0F 43 C8                    cmovnb  rcx, rax
PAGE:0000000140398BC9 8B 01                          mov     eax, [rcx]
PAGE:0000000140398BCB 89 01                          mov     [rcx], eax
PAGE:0000000140398BCD 49 8B 14 24                    mov     rdx, [r12]
PAGE:0000000140398BD1 48 89 54 24 58                 mov     [rsp+98h+CapturedBase], rdx ; CapturedBase = *BaseAddress;
PAGE:0000000140398BD6 49 8B 08                       mov     rcx, [r8]
PAGE:0000000140398BD9 48 89 4C 24 50                 mov     [rsp+98h+CaptureRegionSize], rcx ; CapturedRegionSize = *RegionSize;
PAGE:0000000140398BDE EB 05                          jmp     short loc_140398BE5
PAGE:0000000140398BE0                ; ---------------------------------------------------------------------------
PAGE:0000000140398BE0 E9 BD 00 00 00                 jmp     loc_140398CA2
PAGE:0000000140398BE5                ; ---------------------------------------------------------------------------
PAGE:0000000140398BE5
PAGE:0000000140398BE5                loc_140398BE5:                          ; CODE XREF: NtProtectVirtualMemory+B2j
PAGE:0000000140398BE5                                                        ; NtProtectVirtualMemory+1ADj
PAGE:0000000140398BE5 48 8B 05 24 84+                mov     rax, cs:MmHighestUserAddress ; 合法性校验
PAGE:0000000140398BEC 48 3B D0                       cmp     rdx, rax        ; CapturedBase>MM_HIGHEST_USER_ADDRESS
PAGE:0000000140398BEF 0F 87 11 01 00+                ja      RETURN_STATUS_INVALID_PARAMETER_2
PAGE:0000000140398BF5 48 2B C2                       sub     rax, rdx        ; MM_HIGHEST_USER_ADDRESS64-CapturedBase
PAGE:0000000140398BF8 48 3B C1                       cmp     rax, rcx
PAGE:0000000140398BFB 0F 82 19 01 03+                jb      RETURN_STATUS_INVALID_PARAMETER_3 ; 小于跳转
PAGE:0000000140398C01 48 85 C9                       test    rcx, rcx        ; CapturedRegionSize是否为0
PAGE:0000000140398C04 0F 84 1A 01 03+                jz      RETURN_STATUS_INVALID_PARAMETER_4
PAGE:0000000140398C0A 48 83 64 24 30+                and     [rsp+98h+var_68], 0 ; POBJECT_HANDLE_INFORMATION   NULL
PAGE:0000000140398C10 48 8D 44 24 48                 lea     rax, [rsp+98h+Object]
PAGE:0000000140398C15 48 89 44 24 28                 mov     [rsp+98h+var_70], rax ; Process
PAGE:0000000140398C1A C7 44 24 20 44+                mov     dword ptr [rsp+98h+var_78], 746C6644h ; Tag
PAGE:0000000140398C22 4C 8B 05 F7 83+                mov     r8, cs:PsProcessType ; PsProcessType
PAGE:0000000140398C29 BA 08 00 00 00                 mov     edx, 8          ; PROCESS_VM_OPERATION
PAGE:0000000140398C2E 49 8B CA                       mov     rcx, r10        ; ProcessHandle
PAGE:0000000140398C31 E8 AA D8 FD FF                 call    ObReferenceObjectByHandleWithTag ; NTSTATUS ObReferenceObjectByHandleWithTag(
PAGE:0000000140398C31                                                        ;   _In_      HANDLE                     Handle,
PAGE:0000000140398C31                                                        ;   _In_      ACCESS_MASK                DesiredAccess,
PAGE:0000000140398C31                                                        ;   _In_opt_  POBJECT_TYPE               ObjectType,
PAGE:0000000140398C31                                                        ;   _In_      KPROCESSOR_MODE            AccessMode,
PAGE:0000000140398C31                                                        ;   _In_      ULONG                      Tag,
PAGE:0000000140398C31                                                        ;   _Out_     PVOID                      *Object,
PAGE:0000000140398C31                                                        ;   _Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation
PAGE:0000000140398C31                                                        ; );
PAGE:0000000140398C36 85 C0                          test    eax, eax
PAGE:0000000140398C38 78 68                          js      short loc_140398CA2
PAGE:0000000140398C3A 48 3B 74 24 48                 cmp     rsi, [rsp+98h+Object] ; 是否是当前进程
PAGE:0000000140398C3F 0F 85 99 00 00+                jnz     loc_140398CDE   ; 不是则跳走调用KeAttachProcess
PAGE:0000000140398C45 33 F6                          xor     esi, esi
PAGE:0000000140398C47
PAGE:0000000140398C47                loc_140398C47:                          ; CODE XREF: NtProtectVirtualMemory+1C6j
PAGE:0000000140398C47 48 8D 44 24 40                 lea     rax, [rsp+98h+LastProtect] ; &LastProtect
PAGE:0000000140398C4C 48 89 44 24 20                 mov     [rsp+98h+var_78], rax ; &LastProtect
PAGE:0000000140398C51 44 8B CF                       mov     r9d, edi        ; NewProtect
PAGE:0000000140398C54 4C 8D 44 24 50                 lea     r8, [rsp+98h+CaptureRegionSize] ; CapturedRegionSize
PAGE:0000000140398C59 48 8D 54 24 58                 lea     rdx, [rsp+98h+CapturedBase] ; CapturedBase
PAGE:0000000140398C5E 48 8B 4C 24 48                 mov     rcx, [rsp+98h+Object] ; Process
PAGE:0000000140398C63 E8 B8 F9 FF FF                 call    MiProtectVirtualMemory
PAGE:0000000140398C68 8B F8                          mov     edi, eax
PAGE:0000000140398C6A 89 44 24 44                    mov     [rsp+98h+var_54], eax
PAGE:0000000140398C6E 85 F6                          test    esi, esi        ; 为0则是  调用过KeStackAttachProcess，需要恢复
PAGE:0000000140398C70 0F 85 81 00 00+                jnz     loc_140398CF7   ; 调用KeUnStackDetachProcess
PAGE:0000000140398C76
PAGE:0000000140398C76                loc_140398C76:                          ; CODE XREF: NtProtectVirtualMemory+1D5j
PAGE:0000000140398C76 48 8B 4C 24 48                 mov     rcx, [rsp+98h+Object] ; Object
PAGE:0000000140398C7B E8 C0 17 CF FF                 call    ObfDereferenceObject ; 减少引用计数
PAGE:0000000140398C80 90                             nop
PAGE:0000000140398C81 48 8B 44 24 50                 mov     rax, [rsp+98h+CaptureRegionSize] ; CapturedRegionSize
PAGE:0000000140398C86 49 89 45 00                    mov     [r13+0], rax
PAGE:0000000140398C8A 48 8B 44 24 58                 mov     rax, [rsp+98h+CapturedBase] ; CapturedBase
PAGE:0000000140398C8F 49 89 04 24                    mov     [r12], rax
PAGE:0000000140398C93 8B 44 24 40                    mov     eax, [rsp+98h+LastProtect]
PAGE:0000000140398C97 41 89 06                       mov     [r14], eax
PAGE:0000000140398C9A EB 04                          jmp     short loc_140398CA0
PAGE:0000000140398C9C                ; ---------------------------------------------------------------------------
PAGE:0000000140398C9C 8B 7C 24 44                    mov     edi, [rsp+98h+var_54]
PAGE:0000000140398CA0
PAGE:0000000140398CA0                loc_140398CA0:                          ; CODE XREF: NtProtectVirtualMemory+16Ej
PAGE:0000000140398CA0 8B C7                          mov     eax, edi
PAGE:0000000140398CA2
PAGE:0000000140398CA2                loc_140398CA2:                          ; CODE XREF: NtProtectVirtualMemory+B4j
PAGE:0000000140398CA2                                                        ; NtProtectVirtualMemory+10Cj ...
PAGE:0000000140398CA2 4C 8D 9C 24 90+                lea     r11, [rsp+98h+var_8]
PAGE:0000000140398CAA 49 8B 73 10                    mov     rsi, [r11+10h]
PAGE:0000000140398CAE 49 8B 7B 18                    mov     rdi, [r11+18h]
PAGE:0000000140398CB2 4D 8B 63 20                    mov     r12, [r11+20h]
PAGE:0000000140398CB6 4D 8B 6B 28                    mov     r13, [r11+28h]
PAGE:0000000140398CBA 49 8B E3                       mov     rsp, r11
PAGE:0000000140398CBD 41 5E                          pop     r14
PAGE:0000000140398CBF C3                             retn
PAGE:0000000140398CC0                ; ---------------------------------------------------------------------------
PAGE:0000000140398CC0
PAGE:0000000140398CC0                loc_140398CC0:                          ; CODE XREF: NtProtectVirtualMemory+50j
PAGE:0000000140398CC0 49 8B 08                       mov     rcx, [r8]
PAGE:0000000140398CC3 48 89 4C 24 50                 mov     [rsp+98h+CaptureRegionSize], rcx ; CapturedRegionSize
PAGE:0000000140398CC8 49 8B 14 24                    mov     rdx, [r12]
PAGE:0000000140398CCC 48 89 54 24 58                 mov     [rsp+98h+CapturedBase], rdx ; CapturedBase
PAGE:0000000140398CD1 4C 8B B4 24 C0+                mov     r14, [rsp+98h+OldProtect]
PAGE:0000000140398CD9 E9 07 FF FF FF                 jmp     loc_140398BE5
PAGE:0000000140398CDE                ; ---------------------------------------------------------------------------
PAGE:0000000140398CDE
PAGE:0000000140398CDE                loc_140398CDE:                          ; CODE XREF: NtProtectVirtualMemory+113j
PAGE:0000000140398CDE 48 8D 54 24 60                 lea     rdx, [rsp+98h+ApcState] ; ApcState
PAGE:0000000140398CE3 48 8B 4C 24 48                 mov     rcx, [rsp+98h+Object] ; Process
PAGE:0000000140398CE8 E8 23 87 D1 FF                 call    KeStackAttachProcess ; VOID KeStackAttachProcess(
PAGE:0000000140398CE8                                                        ;   _Inout_ PRKPROCESS   Process,
PAGE:0000000140398CE8                                                        ;   _Out_   PRKAPC_STATE ApcState
PAGE:0000000140398CE8                                                        ; );
PAGE:0000000140398CED BE 01 00 00 00                 mov     esi, 1
PAGE:0000000140398CF2 E9 50 FF FF FF                 jmp     loc_140398C47
PAGE:0000000140398CF7                ; ---------------------------------------------------------------------------
PAGE:0000000140398CF7
PAGE:0000000140398CF7                loc_140398CF7:                          ; CODE XREF: NtProtectVirtualMemory+144j
PAGE:0000000140398CF7 48 8D 4C 24 60                 lea     rcx, [rsp+98h+ApcState]
PAGE:0000000140398CFC E8 1F 84 D1 FF                 call    KeUnstackDetachProcess ;
PAGE:0000000140398CFC                                                        ; VOID KeUnstackDetachProcess(
PAGE:0000000140398CFC                                                        ;   _In_ PRKAPC_STATE ApcState
PAGE:0000000140398CFC                                                        ; );
PAGE:0000000140398D01 E9 70 FF FF FF                 jmp     loc_140398C76
PAGE:0000000140398D06                ; ---------------------------------------------------------------------------
PAGE:0000000140398D06
PAGE:0000000140398D06                RETURN_STATUS_INVALID_PARAMETER_2:      ; CODE XREF: NtProtectVirtualMemory+C3j
PAGE:0000000140398D06 B8 F0 00 00 C0                 mov     eax, 0C00000F0h
PAGE:0000000140398D0B EB 95                          jmp     short loc_140398CA2
PAGE:0000000140398D0B                ; ---------------------------------------------------------------------------
PAGE:0000000140398D0D 90 90 90 90 90+                align 20h
PAGE:0000000140398D0D 90 90 90 90 90+NtProtectVirtualMemory endp
```

　　这里也是根据KernelMode和UserMode的不同而选择性的验证BaseAddress,如果是KernelMode这个地方就没有进行ProbeForWrite验证，直接跳过验证步骤。

## 0x08 总结

　　1.Zw函数会在KiSystemService中将ETHREAD中的PreviousMode改为KernelMode，最后在Nt函数中如果是KernelMode就会跳过对参数是否可写的验证，如果是UserMode就会验证。如果是UserMode，访问内核地址会报错，所以如果内核中直接调用Nt函数，需要手动将PreviousMode修改为KernelMode否则无法访问内核地址，而修改PreviousMode并且通过系统服务表获取SSDT函数这个过程是很复杂的，直接调用内核导出的Zw函数就行，不过在调用Zw函数的时候需要自己对地址的可写性验证。而且通过Zw函数调用会在系统空间堆栈上有个属于本次调用的自陷框架。

　　2.32位下Zw函数会将内核模式保存在CS最后一位上，调用KiSystemService修改PreviousMode为KernelMode，接着跳转到KiFastCallEntry中间的地方，初始化一些寄存器，最后通过call ebx的方式调用Nt函数，最后通过KiSystemExit返回。

　　64位下Zw函数会调用KiServiceInternal，在这个函数中修改PerviousMode为KernelMode，然后跳转到KiSystemCall64中的KiSystemServiceStart部分，接着在KiSystemServiceRepeat部分通过jmp r11调用Nt函数，最后通过KiSystemServiceExit函数返回。