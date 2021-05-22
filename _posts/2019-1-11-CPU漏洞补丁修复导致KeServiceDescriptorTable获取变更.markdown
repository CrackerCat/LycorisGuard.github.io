---
layout: post
title: CPU漏洞补丁修复导致KeServiceDescriptorTable获取变更
date: 2019-1-11 18:17:12 +0900
category: windowsDriver
---
## 一、前言

　　2018年元旦，出现的cpu的漏洞，可以在windows环三直接读取内核数据，windows对该漏洞提供补丁，补丁增加了一个页表，对应的内核处理也增加了，接下来我们看下补丁修复的表象以及对KeServiceDescriptorTable获取的变更。

　　可参考[https://bbs.kafan.cn/thread-2112833-1-1.html](https://bbs.kafan.cn/thread-2112833-1-1.html)

## 二、补丁修复

　　采用的应该是类似LINUX下的KAISER技术，采用shadow 页表技术，R3,R0用不同的页表，内核地址在R3中只有极少数被映射，大部分都无效，R0中的都有效，并且R3地址也都能访问，只通过SMAP和SMEP来进行保护。

#### 1. 在KPROCESS结构体中增加了UserDirectoryTableBase用户页表指针, 新的UserDirectoryTableBase用来保存R3的CR3, 原来的DirectoryTableBase则为R0的CR3

![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2019-01-11/1.png)

　　环三->内核的切换

```cpp
Msr[C0000082]-> KiSystemCall64Shadow
KVASCODE:0000000140295140 KiSystemCall64Shadow proc near          ; DATA XREF: sub_14016C860+34o
KVASCODE:0000000140295140                                         ; KiInitializeBootStructures+288o
KVASCODE:0000000140295140                 swapgs
KVASCODE:0000000140295143                 mov     gs:7010h, rsp
KVASCODE:000000014029514C                 mov     rsp, gs:7000h
KVASCODE:0000000140295155                 bt      dword ptr gs:7018h, 1
KVASCODE:000000014029515F                 jb      short loc_140295164
KVASCODE:0000000140295161                 mov     cr3, rsp
KVASCODE:0000000140295164
KVASCODE:0000000140295164 loc_140295164:                          ; CODE XREF: KiSystemCall64Shadow+1Fj
KVASCODE:0000000140295164                 mov     rsp, gs:7008h
```

　　内核->环三的切换

```cpp
KiSystemServiceExit-> KiKernelSysretExit
KVASCODE:0000000140294C40 KiKernelSysretExit proc near            ; CODE XREF: KiCallUserMode+1B6j
KVASCODE:0000000140294C40                                         ; KiSystemServiceExit+222j ...
KVASCODE:0000000140294C40                 mov     esp, gs:7018h
KVASCODE:0000000140294C48                 bt      esp, 1
KVASCODE:0000000140294C4C                 jb      short loc_140294C84
KVASCODE:0000000140294C4E                 mov     rbp, gs:188h
KVASCODE:0000000140294C57                 mov     rbp, [rbp+_ETHREAD.Tcb.Process]
KVASCODE:0000000140294C5E                 mov     rbp, [rbp+_KPROCESS.UserDirectoryTableBase]
KVASCODE:0000000140294C65                 bt      ebp, 0
KVASCODE:0000000140294C69                 jnb     short loc_140294C81
KVASCODE:0000000140294C6B                 bt      esp, 0
KVASCODE:0000000140294C6F                 jb      short loc_140294C78
KVASCODE:0000000140294C71                 bts     rbp, 3Fh
KVASCODE:0000000140294C76                 jmp     short loc_140294C81
KVASCODE:0000000140294C78 ; ---------------------------------------------------------------------------
KVASCODE:0000000140294C78
KVASCODE:0000000140294C78 loc_140294C78:                          ; CODE XREF: KiKernelSysretExit+2Fj
KVASCODE:0000000140294C78                 and     dword ptr gs:7018h, 0FFFFFFFEh
KVASCODE:0000000140294C81
KVASCODE:0000000140294C81 loc_140294C81:                          ; CODE XREF: KiKernelSysretExit+29j
KVASCODE:0000000140294C81                                         ; KiKernelSysretExit+36j
KVASCODE:0000000140294C81                 mov     cr3, rbp
KVASCODE:0000000140294C84
KVASCODE:0000000140294C84 loc_140294C84:                          ; CODE XREF: KiKernelSysretExit+Cj
KVASCODE:0000000140294C84                 mov     rbp, r9
KVASCODE:0000000140294C87                 mov     rsp, r8
KVASCODE:0000000140294C8A                 swapgs
KVASCODE:0000000140294C8D                 sysret
KVASCODE:0000000140294C90                 retn
KVASCODE:0000000140294C90 KiKernelSysretExit endp
```
　　查看进程中DirectoryTableBase和UserDirectoryTableBase值
```cpp
kd> dt _kprocess ffffa387efa55580
ntdll!_KPROCESS
    +0x028 DirectoryTableBase : 0x31620002
    +0x278 UserDirectoryTableBase : 0x31aa0001
```
　　我们查看UserDirectoryTableBase和DirectoryTableBase内容发现是一样的，因为这里面映射的都是R3的表象，而这些内容在两个表中都有映射

```cpp
kd> !dq 0x31aa0000
#31aa0000 0a000000`3a487867 00000000`00000000
#31aa0010 00000000`00000000 00000000`00000000
#31aa0020 00000000`00000000 00000000`00000000
#31aa0030 00000000`00000000 00000000`00000000
#31aa0040 00000000`00000000 00000000`00000000
#31aa0050 00000000`00000000 00000000`00000000
#31aa0060 00000000`00000000 00000000`00000000
#31aa0070 00000000`00000000 00000000`00000000
kd> !dq 0x31620000
#31620000 0a000000`3a487867 00000000`00000000
#31620010 00000000`00000000 00000000`00000000
#31620020 00000000`00000000 00000000`00000000
#31620030 00000000`00000000 00000000`00000000
#31620040 00000000`00000000 00000000`00000000
#31620050 00000000`00000000 00000000`00000000
#31620060 00000000`00000000 00000000`00000000
#31620070 00000000`00000000 00000000`00000000
```

　　比较重要的nt!KiSystemCall64Shadow在两个表中都有映射，指向同一个物理地址

```cpp
kd> ? nt!kisystemcall64shadow
Evaluate expression: -8779310440128 = fffff803`e851e140
kd> !vtop 0x31aa0000 fffff803e851e140
Amd64VtoP: Virt fffff803`e851e140, pagedir 31aa0000
Amd64VtoP: PML4E 31aa0f80
Amd64VtoP: PDPE 99078
Amd64VtoP: PDE 98a10
Amd64VtoP: PTE c9f8f0
Amd64VtoP: Mapped phys 2f1e140
Virtual address fffff803e851e140 translates to physical address 2f1e140.

kd> !vtop 0x31620000 fffff803e851e140
Amd64VtoP: Virt fffff803`e851e140, pagedir 31620000
Amd64VtoP: PML4E 31620f80
Amd64VtoP: PDPE e09078
Amd64VtoP: PDE e0aa10
Amd64VtoP: PTE e178f0
Amd64VtoP: Mapped phys 2f1e140
Virtual address fffff803e851e140 translates to physical address 2f1e140.
```
　　我们再来看内核地址的映射情况

```cpp
kd> !pcr
KPCR for Processor 0 at fffff803e70f6000:
    Major 1 Minor 1
    NtTib.ExceptionList: fffff803ea464fb0
        NtTib.StackBase: fffff803ea463000
       NtTib.StackLimit: 0000000000000000
     NtTib.SubSystemTib: fffff803e70f6000
          NtTib.Version: 00000000e70f6180
      NtTib.UserPointer: fffff803e70f6870
          NtTib.SelfTib: 00000000002e7000

                SelfPcr: 0000000000000000
                   Prcb: fffff803e70f6180
                   Irql: 0000000000000000
                    IRR: 0000000000000000
                    IDR: 0000000000000000
          InterruptMode: 0000000000000000
                    IDT: 0000000000000000
                    GDT: 0000000000000000
                    TSS: 0000000000000000

          CurrentThread: ffffa387ee521080
             NextThread: 0000000000000000
             IdleThread: fffff803e86a1380

              DpcQueue: Unable to read nt!_KDPC_DATA.DpcListHead.Flink @ fffff803e70f8f80
```

```cpp
kd> !vtop 0x31aa0000 fffff803e70f8f80
Amd64VtoP: Virt fffff803`e70f8f80, pagedir 31aa0000
Amd64VtoP: PML4E 31aa0f80
Amd64VtoP: PDPE 99078
Amd64VtoP: PDE 989c0
Amd64VtoP: PTE e1c7c0
Amd64VtoP: zero PTE
Virtual address fffff803e70f8f80 translation fails, error 0xD0000147.

kd> !vtop 0x31620000 fffff803e70f8f80
Amd64VtoP: Virt fffff803`e70f8f80, pagedir 31620000
Amd64VtoP: PML4E 31620f80
Amd64VtoP: PDPE e09078
Amd64VtoP: PDE e0a9c0
Amd64VtoP: PTE e0d7c0
Amd64VtoP: Mapped phys 1393f80
Virtual address fffff803e70f8f80 translates to physical address 1393f80.
```

　　可以看到地址fffff803e70f8f80只在R0被映射为物理地址，在R3没有映射。

 

## 三、 msr[0xc0000082]变成了KiSystemCall64Shadow函数

　　原来我们64位搜索KeServiceDescriptorTable是通过msr的0xc0000082获得KiSystemCall64字段, 但是现在msr[0xc0000082]变成了KiSystemCall64Shadow函数, 而且这个函数无法直接搜索到KeServiceDescriptorTable。

```cpp
1: kd> rdmsr 0xc0000082
msr[c0000082] = fffff806`0b134140

1: kd> u fffff806`0b134140 l80
nt!KiSystemCall64Shadow:
fffff806`0b134140 0f01f8          swapgs
fffff806`0b134143 654889242510700000 mov   qword ptr gs:[7010h],rsp
fffff806`0b13414c 65488b242500700000 mov   rsp,qword ptr gs:[7000h]
fffff806`0b134155 650fba24251870000001 bt  dword ptr gs:[7018h],1
fffff806`0b13415f 7203            jb      nt!KiSystemCall64Shadow+0x24 (fffff806`0b134164)
fffff806`0b134161 0f22dc          mov     cr3,rsp
fffff806`0b134164 65488b242508700000 mov   rsp,qword ptr gs:[7008h]
nt!KiSystemCall64ShadowCommon:
fffff806`0b13416d 6a2b            push    2Bh
fffff806`0b13416f 65ff342510700000 push    qword ptr gs:[7010h]
fffff806`0b134177 4153            push    r11
fffff806`0b134179 6a33            push    33h
fffff806`0b13417b 51              push    rcx
fffff806`0b13417c 498bca          mov     rcx,r10
fffff806`0b13417f 4883ec08        sub     rsp,8
fffff806`0b134183 55              push    rbp
fffff806`0b134184 4881ec58010000  sub     rsp,158h
fffff806`0b13418b 488dac2480000000 lea     rbp,[rsp+80h]
fffff806`0b134193 48899dc0000000  mov     qword ptr [rbp+0C0h],rbx
fffff806`0b13419a 4889bdc8000000  mov     qword ptr [rbp+0C8h],rdi
fffff806`0b1341a1 4889b5d0000000  mov     qword ptr [rbp+0D0h],rsi
fffff806`0b1341a8 488945b0        mov     qword ptr [rbp-50h],rax
fffff806`0b1341ac 48894db8        mov     qword ptr [rbp-48h],rcx
fffff806`0b1341b0 488955c0        mov     qword ptr [rbp-40h],rdx
fffff806`0b1341b4 65488b0c2588010000 mov   rcx,qword ptr gs:[188h]
fffff806`0b1341bd 488b8920020000  mov     rcx,qword ptr [rcx+220h]
fffff806`0b1341c4 488b8930080000  mov     rcx,qword ptr [rcx+830h]
fffff806`0b1341cb 6548890c2570020000 mov   qword ptr gs:[270h],rcx
fffff806`0b1341d4 658a0c2550080000 mov     cl,byte ptr gs:[850h]
fffff806`0b1341dc 65880c2551080000 mov     byte ptr gs:[851h],cl
fffff806`0b1341e4 658a0c2578020000 mov     cl,byte ptr gs:[278h]
fffff806`0b1341ec 65880c2552080000 mov     byte ptr gs:[852h],cl
fffff806`0b1341f4 650fb604257b020000 movzx eax,byte ptr gs:[27Bh]
fffff806`0b1341fd 653804257a020000 cmp     byte ptr gs:[27Ah],al
fffff806`0b134205 7411            je      nt!KiSystemCall64ShadowCommon+0xab (fffff806`0b134218)
fffff806`0b134207 658804257a020000 mov     byte ptr gs:[27Ah],al
fffff806`0b13420f b948000000      mov     ecx,48h
fffff806`0b134214 33d2            xor     edx,edx
fffff806`0b134216 0f30            wrmsr
fffff806`0b134218 650fb6142578020000 movzx edx,byte ptr gs:[278h]
fffff806`0b134221 f7c208000000    test    edx,8
fffff806`0b134227 7413            je      nt!KiSystemCall64ShadowCommon+0xcf (fffff806`0b13423c)
fffff806`0b134229 b801000000      mov     eax,1
fffff806`0b13422e 33d2            xor     edx,edx
fffff806`0b134230 b949000000      mov     ecx,49h
fffff806`0b134235 0f30            wrmsr
fffff806`0b134237 e93e010000      jmp     nt!KiSystemCall64ShadowCommon+0x20d (fffff806`0b13437a)
fffff806`0b13423c f7c202000000    test    edx,2
fffff806`0b134242 0f842f010000    je      nt!KiSystemCall64ShadowCommon+0x20a (fffff806`0b134377)
fffff806`0b134248 65f604257902000004 test  byte ptr gs:[279h],4
fffff806`0b134251 0f8520010000    jne     nt!KiSystemCall64ShadowCommon+0x20a (fffff806`0b134377)
fffff806`0b134257 e80e010000      call    nt!KiSystemCall64ShadowCommon+0x1fd (fffff806`0b13436a)
fffff806`0b13425c 4883c408        add     rsp,8
fffff806`0b134260 e80e010000      call    nt!KiSystemCall64ShadowCommon+0x206 (fffff806`0b134373)
fffff806`0b134265 4883c408        add     rsp,8
fffff806`0b134269 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0xef (fffff806`0b13425c)
fffff806`0b13426e 4883c408        add     rsp,8
fffff806`0b134272 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0xf8 (fffff806`0b134265)
fffff806`0b134277 4883c408        add     rsp,8
fffff806`0b13427b e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x101 (fffff806`0b13426e)
fffff806`0b134280 4883c408        add     rsp,8
fffff806`0b134284 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x10a (fffff806`0b134277)
fffff806`0b134289 4883c408        add     rsp,8
fffff806`0b13428d e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x113 (fffff806`0b134280)
fffff806`0b134292 4883c408        add     rsp,8
fffff806`0b134296 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x11c (fffff806`0b134289)
fffff806`0b13429b 4883c408        add     rsp,8
fffff806`0b13429f e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x125 (fffff806`0b134292)
fffff806`0b1342a4 4883c408        add     rsp,8
fffff806`0b1342a8 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x12e (fffff806`0b13429b)
fffff806`0b1342ad 4883c408        add     rsp,8
fffff806`0b1342b1 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x137 (fffff806`0b1342a4)
fffff806`0b1342b6 4883c408        add     rsp,8
fffff806`0b1342ba e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x140 (fffff806`0b1342ad)
fffff806`0b1342bf 4883c408        add     rsp,8
fffff806`0b1342c3 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x149 (fffff806`0b1342b6)
fffff806`0b1342c8 4883c408        add     rsp,8
fffff806`0b1342cc e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x152 (fffff806`0b1342bf)
fffff806`0b1342d1 4883c408        add     rsp,8
fffff806`0b1342d5 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x15b (fffff806`0b1342c8)
fffff806`0b1342da 4883c408        add     rsp,8
fffff806`0b1342de e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x164 (fffff806`0b1342d1)
fffff806`0b1342e3 4883c408        add     rsp,8
fffff806`0b1342e7 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x16d (fffff806`0b1342da)
fffff806`0b1342ec 4883c408        add     rsp,8
fffff806`0b1342f0 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x176 (fffff806`0b1342e3)
fffff806`0b1342f5 4883c408        add     rsp,8
fffff806`0b1342f9 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x17f (fffff806`0b1342ec)
fffff806`0b1342fe 4883c408        add     rsp,8
fffff806`0b134302 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x188 (fffff806`0b1342f5)
fffff806`0b134307 4883c408        add     rsp,8
fffff806`0b13430b e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x191 (fffff806`0b1342fe)
fffff806`0b134310 4883c408        add     rsp,8
fffff806`0b134314 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x19a (fffff806`0b134307)
fffff806`0b134319 4883c408        add     rsp,8
fffff806`0b13431d e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1a3 (fffff806`0b134310)
fffff806`0b134322 4883c408        add     rsp,8
fffff806`0b134326 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1ac (fffff806`0b134319)
fffff806`0b13432b 4883c408        add     rsp,8
fffff806`0b13432f e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1b5 (fffff806`0b134322)
fffff806`0b134334 4883c408        add     rsp,8
fffff806`0b134338 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1be (fffff806`0b13432b)
fffff806`0b13433d 4883c408        add     rsp,8
fffff806`0b134341 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1c7 (fffff806`0b134334)
fffff806`0b134346 4883c408        add     rsp,8
fffff806`0b13434a e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1d0 (fffff806`0b13433d)
fffff806`0b13434f 4883c408        add     rsp,8
fffff806`0b134353 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1d9 (fffff806`0b134346)
fffff806`0b134358 4883c408        add     rsp,8
fffff806`0b13435c e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1e2 (fffff806`0b13434f)
fffff806`0b134361 4883c408        add     rsp,8
fffff806`0b134365 e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1eb (fffff806`0b134358)
fffff806`0b13436a 4883c408        add     rsp,8
fffff806`0b13436e e8eeffffff      call    nt!KiSystemCall64ShadowCommon+0x1f4 (fffff806`0b134361)
fffff806`0b134373 4883c408        add     rsp,8
fffff806`0b134377 0faee8          lfence
fffff806`0b13437a 65c604255308000000 mov   byte ptr gs:[853h],0
fffff806`0b134383 e9631ae9ff      jmp     nt!KiSystemServiceUser (fffff806`0afc5deb)
fffff806`0b134388 c3              ret
```

　　可以通过KiSystemServiceUser函数找到我们熟悉的KeServiceDescriptorTable

```cpp
1: kd> u fffff806`0afc5deb l 40
nt!KiSystemServiceUser:
fffff806`0afc5deb c645ab02        mov     byte ptr [rbp-55h],2
fffff806`0afc5def 65488b1c2588010000 mov   rbx,qword ptr gs:[188h]
fffff806`0afc5df8 0f0d8b90000000  prefetchw [rbx+90h]
fffff806`0afc5dff 0fae5dac        stmxcsr dword ptr [rbp-54h]
fffff806`0afc5e03 650fae142580010000 ldmxcsr dword ptr gs:[180h]
fffff806`0afc5e0c 807b0300        cmp     byte ptr [rbx+3],0
fffff806`0afc5e10 66c785800000000000 mov   word ptr [rbp+80h],0
fffff806`0afc5e19 0f84a8000000    je      nt!KiSystemServiceUser+0xdc (fffff806`0afc5ec7)
fffff806`0afc5e1f f6430303        test    byte ptr [rbx+3],3
fffff806`0afc5e23 4c8945c8        mov     qword ptr [rbp-38h],r8
fffff806`0afc5e27 4c894dd0        mov     qword ptr [rbp-30h],r9
fffff806`0afc5e2b 7405            je      nt!KiSystemServiceUser+0x47 (fffff806`0afc5e32)
fffff806`0afc5e2d e84ef6feff      call    nt!KiSaveDebugRegisterState (fffff806`0afb5480)
fffff806`0afc5e32 f6430304        test    byte ptr [rbx+3],4
fffff806`0afc5e36 742e            je      nt!KiSystemServiceUser+0x7b (fffff806`0afc5e66)
fffff806`0afc5e38 4c8955e0        mov     qword ptr [rbp-20h],r10
fffff806`0afc5e3c 4c8955d8        mov     qword ptr [rbp-28h],r10
fffff806`0afc5e40 0f2945f0        movaps  xmmword ptr [rbp-10h],xmm0
fffff806`0afc5e44 0f294d00        movaps  xmmword ptr [rbp],xmm1
fffff806`0afc5e48 0f295510        movaps  xmmword ptr [rbp+10h],xmm2
fffff806`0afc5e4c 0f295d20        movaps  xmmword ptr [rbp+20h],xmm3
fffff806`0afc5e50 0f296530        movaps  xmmword ptr [rbp+30h],xmm4
fffff806`0afc5e54 0f296d40        movaps  xmmword ptr [rbp+40h],xmm5
fffff806`0afc5e58 fb              sti
fffff806`0afc5e59 488bcc          mov     rcx,rsp
fffff806`0afc5e5c e80fcd6400      call    nt!PsPicoSystemCallDispatch (fffff806`0b612b70)
fffff806`0afc5e61 e99f040000      jmp     nt!KiSystemServiceExitPico (fffff806`0afc6305)
fffff806`0afc5e66 f6430380        test    byte ptr [rbx+3],80h
fffff806`0afc5e6a 7448            je      nt!KiSystemServiceUser+0xc9 (fffff806`0afc5eb4)
fffff806`0afc5e6c b9020100c0      mov     ecx,0C0000102h
fffff806`0afc5e71 0f32            rdmsr
fffff806`0afc5e73 48c1e220        shl     rdx,20h
fffff806`0afc5e77 480bc2          or      rax,rdx
fffff806`0afc5e7a 483b050fab1a00  cmp     rax,qword ptr [nt!MmUserProbeAddress (fffff806`0b170990)]
fffff806`0afc5e81 480f430507ab1a00 cmovae  rax,qword ptr [nt!MmUserProbeAddress (fffff806`0b170990)]
fffff806`0afc5e89 483983f0000000  cmp     qword ptr [rbx+0F0h],rax
fffff806`0afc5e90 7422            je      nt!KiSystemServiceUser+0xc9 (fffff806`0afc5eb4)
fffff806`0afc5e92 488b93f0010000  mov     rdx,qword ptr [rbx+1F0h]
fffff806`0afc5e99 0fba6b7408      bts     dword ptr [rbx+74h],8
fffff806`0afc5e9e 66ff8be6010000  dec     word ptr [rbx+1E6h]
fffff806`0afc5ea5 48898280000000  mov     qword ptr [rdx+80h],rax
fffff806`0afc5eac fb              sti
fffff806`0afc5ead e88e120000      call    nt!KiUmsCallEntry (fffff806`0afc7140)
fffff806`0afc5eb2 eb0b            jmp     nt!KiSystemServiceUser+0xd4 (fffff806`0afc5ebf)
fffff806`0afc5eb4 f6430340        test    byte ptr [rbx+3],40h
fffff806`0afc5eb8 7405            je      nt!KiSystemServiceUser+0xd4 (fffff806`0afc5ebf)
fffff806`0afc5eba 0fba6b7410      bts     dword ptr [rbx+74h],10h
fffff806`0afc5ebf 4c8b45c8        mov     r8,qword ptr [rbp-38h]
fffff806`0afc5ec3 4c8b4dd0        mov     r9,qword ptr [rbp-30h]
fffff806`0afc5ec7 488b45b0        mov     rax,qword ptr [rbp-50h]
fffff806`0afc5ecb 488b4db8        mov     rcx,qword ptr [rbp-48h]
fffff806`0afc5ecf 488b55c0        mov     rdx,qword ptr [rbp-40h]
fffff806`0afc5ed3 fb              sti
fffff806`0afc5ed4 48898b88000000  mov     qword ptr [rbx+88h],rcx
fffff806`0afc5edb 898380000000    mov     dword ptr [rbx+80h],eax
fffff806`0afc5ee1 666666666666660f1f840000000000 nop word ptr [rax+rax]
nt!KiSystemServiceStart:
fffff806`0afc5ef0 4889a390000000  mov     qword ptr [rbx+90h],rsp
fffff806`0afc5ef7 8bf8            mov     edi,eax
fffff806`0afc5ef9 c1ef07          shr     edi,7
fffff806`0afc5efc 83e720          and     edi,20h
fffff806`0afc5eff 25ff0f0000      and     eax,0FFFh
nt!KiSystemServiceRepeat:
fffff806`0afc5f04 4c8d1575a93100  lea     r10,[nt!KeServiceDescriptorTable (fffff806`0b2e0880)]
fffff806`0afc5f0b 4c8d1d6e3a3000  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff806`0b2c9980)]
fffff806`0afc5f12 f7437880000000  test    dword ptr [rbx+78h],80h
```