---
layout: post
title: 64位使用windbg获取Shadow SSDT
date: 2018-01-14 17:37:12 +0900
category: windowsDriver
---
首先选择一个带界面的程序比如explorer.exe进行附加
```cpp
kd> !process 0 0 explorer.exe
PROCESS ffff86893dd075c0
SessionId: 1 Cid: 0d48 Peb: 00d50000 ParentCid: 0d30
DirBase: 42d9a000 ObjectTable: ffffe28598bb1800 HandleCount: 1991.
Image: explorer.exe
```

读取msr = 0xC0000082的值

```cpp
kd> .process ffff86893dd075c0
Implicit process is now ffff8689`3dd075c0
WARNING: .cache forcedecodeuser is not enabled
kd> rdmsr 0xc0000082
msr[c0000082] = fffff803`201f7280
```

对读取的值进行反汇编，找到 `KeServiceDescriptorTableShadow` 的地址

```cpp
kd> u fffff803`201f7280 l50
nt!KiSystemCall64:
fffff803`201f7280 0f01f8 swapgs
fffff803`201f7283 654889242510000000 mov qword ptr gs:[10h],rsp
fffff803`201f728c 65488b2425a8010000 mov rsp,qword ptr gs:[1A8h]
fffff803`201f7295 6a2b push 2Bh
fffff803`201f7297 65ff342510000000 push qword ptr gs:[10h]
fffff803`201f729f 4153 push r11
fffff803`201f72a1 6a33 push 33h
fffff803`201f72a3 51 push rcx
fffff803`201f72a4 498bca mov rcx,r10
fffff803`201f72a7 4883ec08 sub rsp,8
fffff803`201f72ab 55 push rbp
fffff803`201f72ac 4881ec58010000 sub rsp,158h
fffff803`201f72b3 488dac2480000000 lea rbp,[rsp+80h]
fffff803`201f72bb 48899dc0000000 mov qword ptr [rbp+0C0h],rbx
fffff803`201f72c2 4889bdc8000000 mov qword ptr [rbp+0C8h],rdi
fffff803`201f72c9 4889b5d0000000 mov qword ptr [rbp+0D0h],rsi
nt!KiSystemServiceUser:
fffff803`201f72d0 c645ab02 mov byte ptr [rbp-55h],2
fffff803`201f72d4 65488b1c2588010000 mov rbx,qword ptr gs:[188h]
fffff803`201f72dd 0f0d8b90000000 prefetchw [rbx+90h]
fffff803`201f72e4 0fae5dac stmxcsr dword ptr [rbp-54h]
fffff803`201f72e8 650fae142580010000 ldmxcsr dword ptr gs:[180h]
fffff803`201f72f1 807b0300 cmp byte ptr [rbx+3],0
fffff803`201f72f5 66c785800000000000 mov word ptr [rbp+80h],0
fffff803`201f72fe 0f84b1000000 je nt!KiSystemServiceUser+0xe5 (fffff803`201f73b5)
fffff803`201f7304 488945b0 mov qword ptr [rbp-50h],rax
fffff803`201f7308 48894db8 mov qword ptr [rbp-48h],rcx
fffff803`201f730c 488955c0 mov qword ptr [rbp-40h],rdx
fffff803`201f7310 f6430303 test byte ptr [rbx+3],3
fffff803`201f7314 4c8945c8 mov qword ptr [rbp-38h],r8
fffff803`201f7318 4c894dd0 mov qword ptr [rbp-30h],r9
fffff803`201f731c 7405 je nt!KiSystemServiceUser+0x53 (fffff803`201f7323)
fffff803`201f731e e80d53ffff call nt!KiSaveDebugRegisterState (fffff803`201ec630)
fffff803`201f7323 f6430304 test byte ptr [rbx+3],4
fffff803`201f7327 742e je nt!KiSystemServiceUser+0x87 (fffff803`201f7357)
fffff803`201f7329 4c8955e0 mov qword ptr [rbp-20h],r10
fffff803`201f732d 4c8955d8 mov qword ptr [rbp-28h],r10
fffff803`201f7331 0f2945f0 movaps xmmword ptr [rbp-10h],xmm0
fffff803`201f7335 0f294d00 movaps xmmword ptr [rbp],xmm1
fffff803`201f7339 0f295510 movaps xmmword ptr [rbp+10h],xmm2
fffff803`201f733d 0f295d20 movaps xmmword ptr [rbp+20h],xmm3
fffff803`201f7341 0f296530 movaps xmmword ptr [rbp+30h],xmm4
fffff803`201f7345 0f296d40 movaps xmmword ptr [rbp+40h],xmm5
fffff803`201f7349 fb sti
fffff803`201f734a 488bcc mov rcx,rsp
fffff803`201f734d e89e105a00 call nt!PsPicoSystemCallDispatch (fffff803`207983f0)
fffff803`201f7352 e900040000 jmp nt!KiSystemServiceExitPico (fffff803`201f7757)
fffff803`201f7357 f6430380 test byte ptr [rbx+3],80h
fffff803`201f735b 7439 je nt!KiSystemServiceUser+0xc6 (fffff803`201f7396)
fffff803`201f735d b9020100c0 mov ecx,0C0000102h
fffff803`201f7362 0f32 rdmsr
fffff803`201f7364 48c1e220 shl rdx,20h
fffff803`201f7368 480bc2 or rax,rdx
fffff803`201f736b 483983f0000000 cmp qword ptr [rbx+0F0h],rax
fffff803`201f7372 7422 je nt!KiSystemServiceUser+0xc6 (fffff803`201f7396)
fffff803`201f7374 488b93f0010000 mov rdx,qword ptr [rbx+1F0h]
fffff803`201f737b 0fba6b7408 bts dword ptr [rbx+74h],8
fffff803`201f7380 66ff8be6010000 dec word ptr [rbx+1E6h]
fffff803`201f7387 48898280000000 mov qword ptr [rdx+80h],rax
fffff803`201f738e fb sti
fffff803`201f738f e8ac0f0000 call nt!KiUmsCallEntry (fffff803`201f8340)
fffff803`201f7394 eb0b jmp nt!KiSystemServiceUser+0xd1 (fffff803`201f73a1)
fffff803`201f7396 f6430340 test byte ptr [rbx+3],40h
fffff803`201f739a 7405 je nt!KiSystemServiceUser+0xd1 (fffff803`201f73a1)
fffff803`201f739c 0fba6b7410 bts dword ptr [rbx+74h],10h
fffff803`201f73a1 488b45b0 mov rax,qword ptr [rbp-50h]
fffff803`201f73a5 488b4db8 mov rcx,qword ptr [rbp-48h]
fffff803`201f73a9 488b55c0 mov rdx,qword ptr [rbp-40h]
fffff803`201f73ad 4c8b45c8 mov r8,qword ptr [rbp-38h]
fffff803`201f73b1 4c8b4dd0 mov r9,qword ptr [rbp-30h]
fffff803`201f73b5 fb sti
fffff803`201f73b6 48898b88000000 mov qword ptr [rbx+88h],rcx
fffff803`201f73bd 898380000000 mov dword ptr [rbx+80h],eax
fffff803`201f73c3 66666666660f1f840000000000 nop word ptr [rax+rax]
nt!KiSystemServiceStart:
fffff803`201f73d0 4889a390000000 mov qword ptr [rbx+90h],rsp
fffff803`201f73d7 8bf8 mov edi,eax
fffff803`201f73d9 c1ef07 shr edi,7
fffff803`201f73dc 83e720 and edi,20h
fffff803`201f73df 25ff0f0000 and eax,0FFFh
nt!KiSystemServiceRepeat:
fffff803`201f73e4 4c8d1595142a00 lea r10,[nt!KeServiceDescriptorTable (fffff803`20498880)]
fffff803`201f73eb 4c8d1dcea22800 lea r11,[nt!KeServiceDescriptorTableShadow (fffff803`204816c0)]
```

KeServiceDescriptorTableShadow 是两张表，第一张是KeServiceDescriptorTable, 第二张才是Shadow SSDT的

```cpp
kd> dq KeServiceDescriptorTableShadow
fffff803`204816c0 fffff803`203d1b40 00000000`00000000
fffff803`204816d0 00000000`000001cc fffff803`203d2274
fffff803`204816e0 ffff8063`9353d000 00000000`00000000
fffff803`204816f0 00000000`00000498 ffff8063`9353e6fc
fffff803`20481700 fffff803`203d1b40 00000000`00000000
fffff803`20481710 00000000`000001cc fffff803`203d2274
fffff803`20481720 ffff8063`9353eba0 00000000`00000000
fffff803`20481730 00000000`00000498 ffff8063`9354029c
```

dd命令，找到的就是Shadow SSDT函数相对于Shadow SSDT Table的偏移

```cpp
kd> dd ffff8063`9353d000
ffff8063`9353d000 ffa4a4c0 ffa4a580 ffa4a640 ffa4a700
ffff8063`9353d010 ffa4a7c1 ffa4a880 ffa4a940 ffa4aa00
ffff8063`9353d020 ffa4aac0 ffa4ab80 ffa4ac43 ffa4ad07
ffff8063`9353d030 ffa4adc0 ffa4ae80 ffa4af40 ffa4b000
ffff8063`9353d040 ffa4b0c0 ffa4b180 ffa4b240 ffa4b300
ffff8063`9353d050 ffa4b3c0 ffa4b480 ffa4b540 ffa4b600
ffff8063`9353d060 ffa4b6c0 ffa4b780 ffa4b840 ffa4b901
ffff8063`9353d070 ffa4b9c0 ffa4ba80 ffa4bb40 ffa4bc04
```
