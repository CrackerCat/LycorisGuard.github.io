---
layout: post
title: 暗云Ⅳ对SATA磁盘MBR Hook探索
date: 2018-12-18 21:22:12 +0900
category: Analyse
---
## 一、背景

　　分析暗云4样本, 参考火绒对暗云4的分析, 对暗云4的MBR相关操作进行分析, 本篇着重查看暗云4在SATA磁盘上对磁盘上MBR的0-3F扇区的Hook隐藏。

## 二、暗云4的MBR隐藏

　　使用工具BOOTICE，查看运行样本前后的第一磁盘扇区，发现运行样本后，第一扇区被改写了，但是重启后第一扇区还是原来的数据。查看相关资料，是由于暗云对MBR进行Hook，对BOOTICE的查看访问，返回了伪造的数据，增加MBR修改后的隐蔽性。

## 三、调试

### 1.使用!devstack \device\harddisk0\dr0查看磁盘设备栈底。

　　可以看出SATA类型磁盘使用atapi作为小端口驱动.

![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/1.png)

### 2.借鉴一张腾讯分析暗云三的MBR隐藏图鉴，其中对于SATA类型应属于方案四。

![2](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/2.png)

### 3.使用!drvobj \drive\atapi f 命令查看atapi驱动信息

　　发现IRP_MJ_INTERNAL_DEVICE_CONTROL并没有异常, 所以事情没有想的那么简单.

![3](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/3.png)

### 4.有了之前的经验，我们顺次在查看设备对象的设备扩展是否正常。（中间重启过系统，所以截图中地址和上面会有差异）

![4](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/4.png)

我们查看attach到msahci设备上的设备扩展，看到了激动人心的Hook哈哈。

![5](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/5.png)

查看该地址，正是暗云Ⅳ申请的地址空间，这里我们就找到了暗云Ⅳ在SATA磁盘类型上的Hook地方。

![6](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/6.png)

### 5.那么设备扩展的偏移是怎么找到的呢？

　　这个函数指针由atapi!AtapiChannelInitialize函数进行赋值的。这个设备由ataport!ChannelAddDevice这个函数进行申请和调用赋值。

　　下图为ATA磁盘系统上, 栈底设备的设备扩展未被Hook的图.

![7](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/7.png)

　　下图为Atapi.sys钟AtapiChannelInitialize函数为设备扩展赋值图.

![8](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/8.png)

### 6.对于ATA和SATA进行比较

　　图中左边是ATA系统上\device\harddisk0\dr0栈底设备的设备扩展Hook, Hook的是atapi!AtapiHwStartIo,以及IRP_SCSI 的hook。右边是SATA系统上\device\harddisk0\dr0栈底attach到msahci驱动上设备的设备扩展Hook, Hook的是msahci!AchiHwStartIo函数.

![9](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/9.png)

## 四、如何Hook

在暗云Ⅳ启动后，对该hook点下硬件断点ba w1 fffffa80`044db310

![10](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/10.png)

这样就能在Hook时断下来，通过Hook代码还原Hook方式。

![11](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/11.png)

同时对这个地址进行!pool指定，就能确定SATA Hook实现在代码块的偏移。这里还是不清楚怎么Hook的，找找在往上一点的代码，Offset：0x5225下断，重启进行调试。

![12](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/12.png)

　　我们找到这个Hook函数将汇编代码贴出来，分析一波这个函数在代码块的+0x5034偏移

```cpp
fffffa80`03dcd034 4c8bdc          mov     r11,rsp
fffffa80`03dcd037 49895b18        mov     qword ptr [r11+18h],rbx
fffffa80`03dcd03b 49896b20        mov     qword ptr [r11+20h],rbp
fffffa80`03dcd03f 56              push    rsi
fffffa80`03dcd040 57              push    rdi
fffffa80`03dcd041 4154            push    r12
fffffa80`03dcd043 4155            push    r13
fffffa80`03dcd045 4156            push    r14
fffffa80`03dcd047 4881ec90000000  sub     rsp,90h
fffffa80`03dcd04e 33c0            xor     eax,eax
fffffa80`03dcd050 4533f6          xor     r14d,r14d
fffffa80`03dcd053 488bd9          mov     rbx,rcx
fffffa80`03dcd056 6645897388      mov     word ptr [r11-78h],r14w
fffffa80`03dcd05b 4989438a        mov     qword ptr [r11-76h],rax
fffffa80`03dcd05f 6645897398      mov     word ptr [r11-68h],r14w
fffffa80`03dcd064 4989439a        mov     qword ptr [r11-66h],rax
fffffa80`03dcd068 66458973b8      mov     word ptr [r11-48h],r14w
fffffa80`03dcd06d 498943ba        mov     qword ptr [r11-46h],rax
fffffa80`03dcd071 66458973a8      mov     word ptr [r11-58h],r14w
fffffa80`03dcd076 498943aa        mov     qword ptr [r11-56h],rax
fffffa80`03dcd07a 498d4b88        lea     rcx,[r11-78h]
fffffa80`03dcd07e 488d15abc2ffff  lea     rdx,[fffffa80`03dc9330]
fffffa80`03dcd085 8944244a        mov     dword ptr [rsp+4Ah],eax
fffffa80`03dcd089 668944244e      mov     word ptr [rsp+4Eh],ax
fffffa80`03dcd08e 8944245a        mov     dword ptr [rsp+5Ah],eax
fffffa80`03dcd092 668944245e      mov     word ptr [rsp+5Eh],ax
fffffa80`03dcd097 664489742430    mov     word ptr [rsp+30h],r14w
fffffa80`03dcd09d 4889442432      mov     qword ptr [rsp+32h],rax
fffffa80`03dcd0a2 8944243a        mov     dword ptr [rsp+3Ah],eax
fffffa80`03dcd0a6 668944243e      mov     word ptr [rsp+3Eh],ax
fffffa80`03dcd0ab 8944247a        mov     dword ptr [rsp+7Ah],eax
fffffa80`03dcd0af 668944247e      mov     word ptr [rsp+7Eh],ax
fffffa80`03dcd0b4 8944246a        mov     dword ptr [rsp+6Ah],eax
fffffa80`03dcd0b8 668944246e      mov     word ptr [rsp+6Eh],ax
fffffa80`03dcd0bd 4d897310        mov     qword ptr [r11+10h],r14
fffffa80`03dcd0c1 ff15b1bfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd0c7 488d157ac2ffff  lea     rdx,[fffffa80`03dc9348]
fffffa80`03dcd0ce 488d4c2450      lea     rcx,[rsp+50h]
fffffa80`03dcd0d3 ff159fbfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd0d9 488d1580c2ffff  lea     rdx,[fffffa80`03dc9360]
fffffa80`03dcd0e0 488d4c2430      lea     rcx,[rsp+30h]
fffffa80`03dcd0e5 ff158dbfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd0eb 488d158ec2ffff  lea     rdx,[fffffa80`03dc9380]
fffffa80`03dcd0f2 488d4c2470      lea     rcx,[rsp+70h]
fffffa80`03dcd0f7 ff157bbfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd0fd 488d1594c2ffff  lea     rdx,[fffffa80`03dc9398]
fffffa80`03dcd104 488d4c2460      lea     rcx,[rsp+60h]
fffffa80`03dcd109 ff1569bfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd10f 4c8b6328        mov     r12,qword ptr [rbx+28h]  赋值\driver\atapi驱动对象地址给r12
fffffa80`03dcd113 488b6b20        mov     rbp,qword ptr [rbx+20h]  \device\harddisk0\dr0 栈底设备对象给rbp
fffffa80`03dcd117 488bcb          mov     rcx,rbx
fffffa80`03dcd11a e8a5fdffff      call    fffffa80`03dccec4
fffffa80`03dcd11f 488d159ac2ffff  lea     rdx,[fffffa80`03dc93c0]
fffffa80`03dcd126 488d8c2480000000 lea     rcx,[rsp+80h]
fffffa80`03dcd12e 898364010000    mov     dword ptr [rbx+164h],eax
fffffa80`03dcd134 ff153ebfffff    call    qword ptr [fffffa80`03dc9078]
fffffa80`03dcd13a 488d9424c8000000 lea     rdx,[rsp+0C8h]
fffffa80`03dcd142 488d8c2480000000 lea     rcx,[rsp+80h]
fffffa80`03dcd14a ff15f0bfffff    call    qword ptr [fffffa80`03dc9140]
fffffa80`03dcd150 4c8b4378        mov     r8,qword ptr [rbx+78h]
fffffa80`03dcd154 bf00020000      mov     edi,200h
fffffa80`03dcd159 4d3bc6          cmp     r8,r14
fffffa80`03dcd15c 7437            je      fffffa80`03dcd195
fffffa80`03dcd15e 4180b8fe01000055 cmp     byte ptr [r8+1FEh],55h
fffffa80`03dcd166 752d            jne     fffffa80`03dcd195
fffffa80`03dcd168 4180b8ff010000aa cmp     byte ptr [r8+1FFh],0AAh
fffffa80`03dcd170 7523            jne     fffffa80`03dcd195
fffffa80`03dcd172 488b4b18        mov     rcx,qword ptr [rbx+18h]
fffffa80`03dcd176 488d8424c0000000 lea     rax,[rsp+0C0h]
fffffa80`03dcd17e 448bcf          mov     r9d,edi
fffffa80`03dcd181 b201            mov     dl,1
fffffa80`03dcd183 4c89b424c0000000 mov     qword ptr [rsp+0C0h],r14
fffffa80`03dcd18b 4889442420      mov     qword ptr [rsp+20h],rax
fffffa80`03dcd190 e8a7f1ffff      call    fffffa80`03dcc33c
fffffa80`03dcd195 4c8b4378        mov     r8,qword ptr [rbx+78h]
fffffa80`03dcd199 488b4b18        mov     rcx,qword ptr [rbx+18h] \device\harddisk0\dr0 设备栈倒数第二个设备赋值给rcx
fffffa80`03dcd19d 488d8424c0000000 lea     rax,[rsp+0C0h]
fffffa80`03dcd1a5 448bcf          mov     r9d,edi
fffffa80`03dcd1a8 33d2            xor     edx,edx
fffffa80`03dcd1aa 4889442420      mov     qword ptr [rsp+20h],rax
fffffa80`03dcd1af 4889bc24c0000000 mov     qword ptr [rsp+0C0h],rdi
fffffa80`03dcd1b7 e880f1ffff      call    fffffa80`03dcc33c
fffffa80`03dcd1bc 413bc6          cmp     eax,r14d
fffffa80`03dcd1bf 8bf0            mov     esi,eax
fffffa80`03dcd1c1 0f8c79020000    jl      fffffa80`03dcd440
fffffa80`03dcd1c7 8b8338010000    mov     eax,dword ptr [rbx+138h]
fffffa80`03dcd1cd be020000c0      mov     esi,0C0000002h
fffffa80`03dcd1d2 83f805          cmp     eax,5
fffffa80`03dcd1d5 7545            jne     fffffa80`03dcd21c   ;;跳转
fffffa80`03dcd1d7 498d442460      lea     rax,[r12+60h]

fffffa80`03dcf1dc 4c3930          cmp     qword ptr [rax],r14
fffffa80`03dcf1df 0f84d0010000    je      fffffa80`03dcf3b5
fffffa80`03dcf1e5 488d3d6cf7ffff  lea     rdi,[fffffa80`03dce958]
fffffa80`03dcf1ec 498bcc          mov     rcx,r12
fffffa80`03dcf1ef 48898348010000  mov     qword ptr [rbx+148h],rax
fffffa80`03dcf1f6 488bd7          mov     rdx,rdi
fffffa80`03dcf1f9 e8f2f0ffff      call    fffffa80`03dce2f0
fffffa80`03dcf1fe 48894330        mov     qword ptr [rbx+30h],rax
fffffa80`03dcf202 488b03          mov     rax,qword ptr [rbx]
fffffa80`03dcf205 48894508        mov     qword ptr [rbp+8],rax
fffffa80`03dcf209 c6831001000001  mov     byte ptr [rbx+110h],1
fffffa80`03dcf210 4889bb50010000  mov     qword ptr [rbx+150h],rdi
fffffa80`03dcf217 e999010000      jmp     fffffa80`03dcf3b5
fffffa80`03dcf21c 83f806          cmp     eax,6              ;;;继续执行
fffffa80`03dcf21f 0f8593010000    jne     fffffa80`03dcf3b8
fffffa80`03dcf225 488b6d40        mov     rbp,qword ptr [rbp+40h] ;;;获得DeviceObject->DeviceExtension
fffffa80`03dcd229 493bee          cmp     rbp,r14
fffffa80`03dcd22c 0f8486010000    je      fffffa80`03dcd3b8
fffffa80`03dcd232 488bcd          mov     rcx,rbp
fffffa80`03dcd235 ff15bdbeffff    call    qword ptr [fffffa80`03dc90f8]  ;;Call MmIsValidAddress
fffffa80`03dcd23b 413ac6          cmp     al,r14b
fffffa80`03dcd23e 0f8474010000    je      fffffa80`03dcd3b8
fffffa80`03dcd244 498b4c2418      mov     rcx,qword ptr [r12+18h]  ;;DriverObject->DriverStart
fffffa80`03dcd249 488d542440      lea     rdx,[rsp+40h]
fffffa80`03dcd24e e869faffff      call    fffffa80`03dcccbc ;;修改rbp值
fffffa80`03dcd253 413ac6          cmp     al,r14b           ;; al = 1
fffffa80`03dcd256 0f85f6000000    jne     fffffa80`03dcd352 ;; 跳转
fffffa80`03dcd25c 498b4c2418      mov     rcx,qword ptr [r12+18h]
fffffa80`03dcd261 488d542450      lea     rdx,[rsp+50h]
fffffa80`03dcd266 e851faffff      call    fffffa80`03dcccbc
fffffa80`03dcd26b 413ac6          cmp     al,r14b
fffffa80`03dcd26e 0f85de000000    jne     fffffa80`03dcd352
fffffa80`03dcd274 498b4c2418      mov     rcx,qword ptr [r12+18h]
fffffa80`03dcd279 488d542460      lea     rdx,[rsp+60h]
fffffa80`03dcd27e e839faffff      call    fffffa80`03dcccbc
fffffa80`03dcd283 413ac6          cmp     al,r14b
fffffa80`03dcd286 0f848f000000    je      fffffa80`03dcd31b
fffffa80`03dcd28c 488dbd40010000  lea     rdi,[rbp+140h]
fffffa80`03dcd293 458bee          mov     r13d,r14d
fffffa80`03dcd296 488bcf          mov     rcx,rdi
fffffa80`03dcd299 ff1559beffff    call    qword ptr [fffffa80`03dc90f8]
fffffa80`03dcd29f 413ac6          cmp     al,r14b
fffffa80`03dcd2a2 7412            je      fffffa80`03dcd2b6
fffffa80`03dcd2a4 488b0f          mov     rcx,qword ptr [rdi]
fffffa80`03dcd2a7 488d542430      lea     rdx,[rsp+30h]
fffffa80`03dcd2ac e80bfaffff      call    fffffa80`03dcccbc
fffffa80`03dcd2b1 413ac6          cmp     al,r14b
fffffa80`03dcd2b4 7548            jne     fffffa80`03dcd2fe
fffffa80`03dcd2b6 41ffc5          inc     r13d
fffffa80`03dcd2b9 4883c708        add     rdi,8
fffffa80`03dcd2bd 4183fd10        cmp     r13d,10h
fffffa80`03dcd2c1 72d3            jb      fffffa80`03dcd296
fffffa80`03dcd2c3 488dbdc0000000  lea     rdi,[rbp+0C0h]
fffffa80`03dcd2ca 418bee          mov     ebp,r14d
fffffa80`03dcd2cd 488bcf          mov     rcx,rdi
fffffa80`03dcd2d0 ff1522beffff    call    qword ptr [fffffa80`03dc90f8]
fffffa80`03dcd2d6 413ac6          cmp     al,r14b
fffffa80`03dcd2d9 7412            je      fffffa80`03dcd2ed
fffffa80`03dcd2db 488b0f          mov     rcx,qword ptr [rdi]
fffffa80`03dcd2de 488d542430      lea     rdx,[rsp+30h]
fffffa80`03dcd2e3 e8d4f9ffff      call    fffffa80`03dcccbc
fffffa80`03dcd2e8 413ac6          cmp     al,r14b
fffffa80`03dcd2eb 7511            jne     fffffa80`03dcd2fe
fffffa80`03dcd2ed ffc5            inc     ebp
fffffa80`03dcd2ef 4883c708        add     rdi,8
fffffa80`03dcd2f3 83fd10          cmp     ebp,10h
fffffa80`03dcd2f6 0f83bc000000    jae     fffffa80`03dcd3b8
fffffa80`03dcd2fc ebcf            jmp     fffffa80`03dcd2cd
fffffa80`03dcd2fe 488d0db7f7ffff  lea     rcx,[fffffa80`03dccabc]
fffffa80`03dcd305 c6831201000001  mov     byte ptr [rbx+112h],1
fffffa80`03dcd30c 488bc1          mov     rax,rcx
fffffa80`03dcd30f 488707          xchg    rax,qword ptr [rdi]
fffffa80`03dcd312 48894340        mov     qword ptr [rbx+40h],rax
fffffa80`03dcd316 e98c000000      jmp     fffffa80`03dcd3a7
fffffa80`03dcd31b 488dbdc0000000  lea     rdi,[rbp+0C0h]
fffffa80`03dcd322 418bee          mov     ebp,r14d
fffffa80`03dcd325 488bcf          mov     rcx,rdi
fffffa80`03dcd328 ff15cabdffff    call    qword ptr [fffffa80`03dc90f8]
fffffa80`03dcd32e 413ac6          cmp     al,r14b
fffffa80`03dcd331 7412            je      fffffa80`03dcd345
fffffa80`03dcd333 488b0f          mov     rcx,qword ptr [rdi]
fffffa80`03dcd336 488d542430      lea     rdx,[rsp+30h]
fffffa80`03dcd33b e87cf9ffff      call    fffffa80`03dcccbc
fffffa80`03dcd340 413ac6          cmp     al,r14b
fffffa80`03dcd343 75b9            jne     fffffa80`03dcd2fe
fffffa80`03dcd345 ffc5            inc     ebp
fffffa80`03dcd347 4883c708        add     rdi,8
fffffa80`03dcd34b 83fd10          cmp     ebp,10h
fffffa80`03dcd34e 7368            jae     fffffa80`03dcd3b8
fffffa80`03dcd350 ebd3            jmp     fffffa80`03dcd325
fffffa80`03dcd352 488b7d58        mov     rdi,qword ptr [rbp+58h]  ;;此时rbp+58h保存的就是atapi倒数第三个设备的设备扩展地址;;DeviceObject->DeviceExtension+58h
fffffa80`03dcd356 4881c770010000  add     rdi,170h ;;找到msahci!AhciHwStartIo
fffffa80`03dcd35d 488bcf          mov     rcx,rdi
fffffa80`03dcd360 ff1592bdffff    call    qword ptr [fffffa80`03dc90f8]
fffffa80`03dcd366 413ac6          cmp     al,r14b
fffffa80`03dcd369 744d            je      fffffa80`03dcd3b8
fffffa80`03dcd36b 488b0f          mov     rcx,qword ptr [rdi]
fffffa80`03dcd36e 488d542440      lea     rdx,[rsp+40h]
fffffa80`03dcd373 e844f9ffff      call    fffffa80`03dcccbc
fffffa80`03dcd378 413ac6          cmp     al,r14b
fffffa80`03dcd37b 7512            jne     fffffa80`03dcd38f
fffffa80`03dcd37d 488b0f          mov     rcx,qword ptr [rdi]
fffffa80`03dcd380 488d542450      lea     rdx,[rsp+50h]
fffffa80`03dcd385 e832f9ffff      call    fffffa80`03dcccbc
fffffa80`03dcd38a 413ac6          cmp     al,r14b
fffffa80`03dcd38d 7429            je      fffffa80`03dcd3b8
fffffa80`03dcd38f 488d0d8ef7ffff  lea     rcx,[fffffa80`03dccb24]
fffffa80`03dcd396 c6831101000001  mov     byte ptr [rbx+111h],1
fffffa80`03dcd39d 488bc1          mov     rax,rcx
fffffa80`03dcd3a0 488707          xchg    rax,qword ptr [rdi]
fffffa80`03dcd3a3 48894338        mov     qword ptr [rbx+38h],rax
fffffa80`03dcd3a7 48898b50010000  mov     qword ptr [rbx+150h],rcx
fffffa80`03dcd3ae 4889bb48010000  mov     qword ptr [rbx+148h],rdi
fffffa80`03dcd3b5 418bf6          mov     esi,r14d
fffffa80`03dcd3b8 b9000000c0      mov     ecx,0C0000000h
fffffa80`03dcd3bd 8bc6            mov     eax,esi
fffffa80`03dcd3bf 4488b342010000  mov     byte ptr [rbx+142h],r14b
fffffa80`03dcd3c6 23c1            and     eax,ecx
fffffa80`03dcd3c8 3bc1            cmp     eax,ecx
fffffa80`03dcd3ca 7531            jne     fffffa80`03dcd3fd
fffffa80`03dcd3cc 498b9424e8000000 mov     rdx,qword ptr [r12+0E8h]
fffffa80`03dcd3d4 488d4b58        lea     rcx,[rbx+58h]
fffffa80`03dcd3d8 41b820000000    mov     r8d,20h
fffffa80`03dcd3de e87d060000      call    fffffa80`03dcda60
fffffa80`03dcd3e3 4c8d1d2ef9ffff  lea     r11,[fffffa80`03dccd18]
fffffa80`03dcd3ea 4d879c24e8000000 xchg    r11,qword ptr [r12+0E8h]
fffffa80`03dcd3f2 c6834201000001  mov     byte ptr [rbx+142h],1
fffffa80`03dcd3f9 4c895b50        mov     qword ptr [rbx+50h],r11
fffffa80`03dcd3fd 488d8b90000000  lea     rcx,[rbx+90h]
fffffa80`03dcd404 ff155ebdffff    call    qword ptr [fffffa80`03dc9168]
fffffa80`03dcd40a 488d1587fbffff  lea     rdx,[fffffa80`03dccf98]
fffffa80`03dcd411 488d8bd0000000  lea     rcx,[rbx+0D0h]
fffffa80`03dcd418 e923000000      jmp     fffffa80`03dcd440
fffffa80`03dcd41d 90              nop
fffffa80`03dcd41e 90              nop
fffffa80`03dcd41f 90              nop
fffffa80`03dcd420 90              nop
```

 　　可以看到暗云Ⅳ首先获得\device\harddisk0\dr0栈底设备对象DeviceObj，获得DeviceObj->DeviceExtension, 在通过DeviceObj->DeviceExtension+58h获得attach到msahci驱动是的设备扩展。这样就找到了Hook的地方。
 
 ![14](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/13.png)
 
## 五、系统赋值与寻址

### 1. \device\harddisk0\dr0堆栈以及channel堆栈

![15](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/14.png)

　　我们分析下ataport!DeviceAllocatePdo函数，根据调试所得，DeviceAllocatePdo的第一个参数是channel驱动创建设备的设备对象，具体可参考5.2小节.

![16](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/15.png)

　　我们在看下GenPnpAllocatePdo函数

![17](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/16.png)

　　该函数为ataport创建了一个设备对象，并为这个设备对象的DeviceExtension完成初始化工作。在InsertPdoExtension函数中，完成channelPdoDev指针赋值保存在ataport!PdoDevExtension中的过程，后面我们会继续分析如何通过这个指针进行对磁盘的访问.

![18](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/17.png)

　　根据上面分析, 和当前堆栈, 可以看出访问\device\harddisk0\dr0的Irp, 会被atapi的IdeDeviceP2T0L0-4（PDO） DevExt+0x58(64位)地方获取到atapi的IdePort2（FDO） DevExt, 在通过FDO的DevExt+0x170(64位)获取到msahci!AhciHwStartIo函数进行磁盘访问.

 

### 2.ataport通过ChannelAddDevice为atapi创建FDO和PDO设备

　　对ataport!ChannelAddDevice和ataport!DeviceAllocatePdo下断点, 重启调试,发现ataport!ChannelAddDevice首先中断下来.

　　ataport!ChannelAddDevice第一、第二参数分别是创建设备对象的DriverObject和新建设备需要Attach的Lower设备对象.可以看到是为atapi创建设备对象IdePort0，栈底设备为intelide的PDO设备PciIde0Channel0.

![19](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/18.png)

　　在atapi创建两个FDO后，系统中断在ataport!DeviceAllocatePdo，此时是ataport调用IdeEnumerateDevices枚举每个channel上的设备,并且为atapi创建PDO.

![20](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/19.png)

 　　我们查看ataport!IdeEnumerateDevices的第一个参数0x85cfb0e0正好是atapi的FDO设备IdePort0的DevExt的值, 而且后续将这个DevExt值赋值在PDO的Ext+0x38的位置(x86系统), 说明系统在为IdePort0的FDO创建PDO设备.
 
 ![21](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/20.pngg)
 
 　　再次中断在ataport!IdeEnumerateDevices, 从参数可以看出, 现在为IdePort1的FDO设备创建PDO设备.
 
 ![22](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/21.png)
 
 　　第三次中断在ataport!DeviceAllocatePdo函数, 但现在我们发现atapi的设备只有三个, 前面为IdePort0设备创建的PDO设备被删除了, 而这时候传参还是IdePort0的DevExt参数, 联想到SATA接口\device\harddisk0\dr0堆栈最后磁盘访问使用msahci创建的PDO设备, 可以推断出是SATA接口在为intelide创建PDO时出错, 会自动删除PDO设备, 最后系统使用msahci创建PDO作为磁盘访问引导.
 
 ![23](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/22.png)
 
 　　第三次中断在ataport!ChannelAddDevice时, 我们看到之前atapi创建的PDO都不存在了, 只剩下前两次创建的FDO， 可以看到这次是为atapi创建设备对象 ，栈底设备为msahci的PDO设备PciIde1Channel0
 
 ![24](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/23.png)
 
 　　最后连续调用ataport!ChannelAddDevice为atapi创建FDO设备, 分别attach到msahci的PciIde1Channel0-29上。

　　再次中断在ataport!DeviceAllocatePdo上，可以看到这次使用的IdePort2的设备的DevExt创建atapi的PDO设备

![25](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/24.png)

　　同样ataport!DeviceAllocatePdo会再次中断，依次使用创建的FDO的DevExt创建atapi的PDO设备，最后剩下两个真实有效的PDO分别关联IdePort2和IdePort3设备

![26](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/25.png)

### 3.ataport寻址进行磁盘访问

　　参考之前断下来的堆桟

![27](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/26.png)

ataport!IdeStartDeviceRequest在atapi PDO的DevExt+0x58(64位)的地方找到之前赋值的atapi FDO的DevExt参数

![28](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/27.png)

ataport!IdeStartCrbSynchronized这时候获取的参数就是atapi Fdo的DevExt

![29](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/28.png)

ataport!CallMiniPortHwStartIo在atapi FDO DevExt+0xD8(64位)的地方调用HwStartIo

![30](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/29.png)

### 4. 磁盘disk驱动attach到atapi的PDO

![31](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/30.png)

## 六、XP上的Hook

### 6.1.!devstack \device\harddisk\dr0 指令获取磁盘堆栈

![32](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/31.png)

### 6.2.dt _DRIVER_OBJECT 898f5800 查看当前的\Driver\atapi驱动对象，可以看到DriverStartIo是正常的

![33](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/32.png)

### 6.3.通过设备栈中设备对象!devobj 89945d98，去寻找真正的IdePort1的通道，我们又找到一个\Driver\atapi的对象 89a148c8

![34](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/33.png)

### 6.4.再去查看\Driver\atapi 89a148c8的信息，我们发现DriverStartIo被Hook了

![35](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/34.png)

### 6.5.回过头再来看!devstack \device\harddisk\dr0 指令获取磁盘堆栈上的设备刚好是伪造的设备

![36](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2018-12-18/35.png)

## 七、总结

　　看来SATA与ATA类型hook的实体不一致，ATA hook的是atapi栈底设备的设备扩展中的atapi!AtapiHwStartIo函数，SATA Hook的是atapi栈底设备, attach在msachi上设备的设备扩展中的msachi!AchiHwStartIo函数. Hook类型方式都是一样，只是执行的实体不一致。

　　atapi创建的PDO, 是\device\harddisk0\dr0的栈底设备

　　disk创建设备, attach到atapi的PDO设备上

　　atapi创建的FDO, attach到channel的设备上，其DevExt保存msahci/atapi的HwStartIo函数, 该DevExt指针通过DeviceAllocatePdo保存在atapi的PDO的DevExt中.

　　磁盘访问就是atapi!PDO->Ext->(FDO->Ext)   ----> FDO->Ext   ----> HwStartIo   