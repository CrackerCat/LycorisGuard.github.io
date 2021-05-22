---
layout: post
title: Windows xp下IDT Hook和GDT的学习
date: 2016-04-03 20:47:12 +0900
category: windowsDriver
---
## 一、前言
　　对于IDT第一次的认知是int 2e ，在系统调用的时候原来R3进入R0的方式就是通过int 2e自陷进入内核，然后进入KiSystemService函数，在根据系统服务调用号调用系统服务函数。而2e就是IDT（系统中断描述符表）中的索引位2e的项，而KiSystemService就是该项的例程函数，后来为了提升效率，有了系统快速调用，intel的的cpu通过sysenter指令快速进入内核，直接通过kiFastCallEntry函数调用系统服务函数，各种杀软也做了这个地方的Hook来监控系统调用。因为每次中断都从IDT表中查找2e的那一项的例程函数，会降低效率。

　　最近在做调试器，对于int 3比较熟悉，也遇到各种问题，比如在R3下int 3断点的时候，用WaitForDebugEvent等待异常事件，第一次的时候FirstChance==TRUE，异常恢复的地方就在断点的后一个指令，在FirstChance==FALSE的时候，异常恢复的地址却是断点所在的地方，理论上来说，int 3属于陷阱类异常，恢复的地址是断点的后一个指令地址，但是在FirstChance==FALSE的时候EIP却是当前断点的地址。当时真的是非常不解，后来看了<软件调试>,上面说KiTrap03在内核做了一些事。

　　在windows系统中，操作系统的断点异常处理函数(KiTrap03)对于x86CPU的断点异常会有一个特殊的处理
```cpp
    .text:00436CF5 mov     ebx, [ebp+68h]      
    .text:00436CF8 dec     ebx                  
    .text:00436CF9 mov     ecx, 3                
    .text:00436CFE mov     eax, 80000003h      
    .text:00436D03 call    CommonDispatchException ; 处理异常
```
　　出于这个原因，我们在调试器看到的程序指针仍然指向的是INT 3指令的位置。

　　而KiTrap03就是int 3的例程函数，3就是IDT表中的索引。

　　于是对于IDT中KiTrap03的Hook有了一些学习，在学习中也产生一些问题，不过特别注意不能对KiTrap03下断点，不然会死循环，系统直接卡死。

## 二、IDT hook
### 1、基本思路：
　　IDT(Interrupt Descriptor Table)中断描述符表，是用来处理中断的。中断就是停下现在的活动，去完成新的任务。一个中断可以起源于软件或硬件。比如，软件中断int 3断点，调用IDT中的0x3，出现页错误，调用IDT中的0x0E。或用户进程请求系统服务(SSDT)时，调用IDT中的0x2E。我们现在就想办法，先在系统中找到IDT，然后确定0x3在IDT中的地址，最后用我们的函数地址去取代它，可以去监控是否是当前进程被调试。

 

### 2、需解决的问题：从上面分析可以看出，我们大概需要解决这几个问题：

#### 1．IDT的获取

　　①可以通过SIDT指令，它可以在内存中找到IDT，返回一个IDTR结构的地址。

　　②也可以通过kpcr结构获取，这个结构我们后面再说。

```cpp
typedef struct
{
    WORD IDTLimit;
    WORD LowIDTbase;//IDT的低半地址
    WORD HiIDTbase;//IDT的高半地址
}IDTINFO;

IDTINFO Idtr;
__asm sidt Idtr
//方便获取地址存取的宏
#define MAKELONG(a,b)((LONG)(((WORD)(a))|((DWORD)((WORD)(b)))<<16))
```

```cpp
#pragma pack(1)
typedef struct
{
    WORD LowOffset;           //入口的低半地址
    WORD selector;
    BYTE unused_lo;
    unsigned char unused_hi:5;     // stored TYPE ?
    unsigned char DPL:2;
    unsigned char P:1;         // vector is present
    WORD HiOffset;          //入口地址的低半地址
} IDTENTRY;
#pragma pack()
```
    在windbg中可以通过!idt -a命令查看所有idt中例程的地址

    在每项中我们看到有LowOffset和HiOffset这两个成员，这两个成员构成了处理例程的高4位和低4位。

    知道了这个入口结构,就相当于知道了每间房（可以把IDT看作是一排有256间房组成的线性结构）的长度，我们先获取所有的入口idt_entrys，那么第0x3个房间的地址也就可以确定了，即idt_entrys[0x3]。

 

#### 2.修改IDT表项中的LowOffset和HiOffset来修改IDT例程
```cpp
DWORD KiRealSystemServiceISR_Ptr; // 真正的2E句柄，保存以便恢复hook
#define NT_SYSTEM_SERVICE_INT 0x3
//我们的hook函数
int HookInterrupts()
{

    IDTINFO idt_info;          //SIDT将返回的结构
    IDTENTRY* idt_entries;    //IDT的所有入口
    IDTENTRY* int2e_entry;    //我们目标的入口
    __asm{
        sidt idt_info;         //获取IDTINFO
    }
    //获取所有的入口
    idt_entries =
        (IDTENTRY*)MAKELONG(idt_info.LowIDTbase,idt_info.HiIDTbase);

    //保存真实的0x3地址
    KiRealSystemServiceISR_Ptr = 
       MAKELONG(idt_entries[NT_SYSTEM_SERVICE_INT].LowOffset,

    idt_entries[NT_SYSTEM_SERVICE_INT].HiOffset);
    //获取0x3的入口地址
    int2e_entry = &(idt_entries[NT_SYSTEM_SERVICE_INT]);


    __asm{
        cli;                       // 屏蔽中断，防止被打扰
        lea eax,MyKiSystemService; // 获得我们hook函数的地址，保存在eax
        mov ebx, int2e_entry;      // 0x2E在IDT中的地址，ebx中分地高两个半地址
        mov [ebx],ax;              // 把我们hook函数的低半地址写入真是第半地址
        shr eax,16                 //eax右移16，得到高半地址
        mov [ebx+6],ax;           // 写入高半地址
        sti;                      //开中断
    }
    return 0;

```
#### 3.修改完成

　　在替换成功之后，我们可以查看idt中已经使我们函数的地址了

![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-04-03/1.png)

#### 4.过滤函数处理

　　①.对于NewKiTrap03的处理，我们按照KiTrap03中一样构造陷阱帧，获得当前寄存器的值
```cpp
_declspec(naked) void NewKiTrap03()
{    __asm
    {
            push 0
            mov word ptr [esp+2],0
            push ebp 
            push ebx
            push esi
            push edi
            push fs
            mov ebx,30h
            mov fs,bx
            mov ebx,dword ptr fs:[0]
            push ebx
            sub esp,4h
            push eax
            push ecx
            push edx
            push ds
            push es
            push gs
            mov ax,23h
            sub esp,30h//以上构造
            push esp //陷阱帧首地址
            call FilterExceptionInfo
            add esp,30h//恢复现场
            pop gs
            pop es
            pop ds
            pop edx
            pop ecx
            pop eax
            add esp,4h
            pop ebx
            pop fs
            pop edi
            pop esi
            pop ebx
            pop ebp
            add esp,4h
            jmp g_OrigKiTrap03//跳回老函数
    }
}

VOID __stdcall FilterExceptionInfo(PKTRAP_FRAME pTrapFrame)
{

　　//eip的值减一过int3，汇编代码分析中dec， 
　　DbgPrint("Eip:%x\r\n",(pTrapFrame->Eip)-1);
}
```

　　②.在NewKiTrap03函数中可以获得当前进程的信息，比较当前进程是否被下断点
```cpp
#pragma pack(1)
__declspec(naked) void NewKiTrap03()
{
    __asm
    {
        pushfd          // 保存标志寄存器
        pushad          // 保存所有的通用寄存器
        push  fs
        __asm
        {
            mov     ebx, 30H  // Set FS to PCR.
            mov     fs, bx
        }
        call MyUserFilter   //过滤函数
        pop    fs
        popad          // 恢复通用寄存器
        popfd          // 恢复标志寄存器
        jmp ulAddress    // 跳到原来的中断服务程序
    
    }    
}
#pragma pack()

VOID MyUserFilter()
{
    KdPrint(("Crurrent IRQL: %d\n",KeGetCurrentIrql()));
    if (Eprocess_DebugPort > 0)
    {
        //__asm int 3
        PEPROCESS pEprocess = PsGetCurrentProcess();
        ULONG eprocess = (ULONG)pEprocess;
        char strProcessPath[256] = {'\0'};
        GetProcessName(eprocess, strProcessPath);
        
        PULONG pDebugPort = (PULONG)(eprocess+Eprocess_DebugPort);
　　　　　　UCHAR* ImageFileName = NULL;
　　　　　　if (EPROCESS_ImageFileName_Offset)
　　　　　　{
　　　　　　　　ImageFileName = (PUCHAR)(eprocess + EPROCESS_ImageFileName_Offset); //可以做一些处理
　　　　　　}

if (*pDebugPort > 0)
        {
            KdPrint(("DebugObject = %x\n", pDebugPort));
            *pDebugPort = 0; //clear DebugPort
        }
    }
}


BOOL GetProcessName(ULONG eprocess,CHAR ProcessName[MAX_PATH])
{
    ULONG object;
    PFILE_OBJECT FilePointer;
    ANSI_STRING strProcessName = {0};
    int num = 0;

    if(MmIsAddressValid((PULONG)(eprocess+0x138)))//Eprocess->sectionobject(0x138)
    {
        object=(*(PULONG)(eprocess+0x138));
        KdPrint(("[GetProcessFileName] sectionobject :0x%x\n",object));
        if(MmIsAddressValid((PULONG)((ULONG)object+0x014)))
        {
            object=*(PULONG)((ULONG)object+0x014);
            KdPrint(("[GetProcessFileName] Segment :0x%x\n",object));
            if(MmIsAddressValid((PULONG)((ULONG)object+0x0)))
            {
                object=*(PULONG)((ULONG_PTR)object+0x0);
                KdPrint(("[GetProcessFileName] ControlAera :0x%x\n",object));
                if(MmIsAddressValid((PULONG)((ULONG)object+0x024)))
                {
                    object=*(PULONG)((ULONG)object+0x024);
                    KdPrint(("[GetProcessFileName] FilePointer :0x%x\n",object));
                }
                else
                    return FALSE;
            }
            else
                return FALSE;
        }
        else
            return FALSE;
    }
    else
        return FALSE;

    FilePointer=(PFILE_OBJECT)object;
    RtlUnicodeStringToAnsiString(&strProcessName, &FilePointer->FileName, TRUE);
    for (int i = strProcessName.Length - 1; i >= 0; i--)
    {
        if (strProcessName.Buffer[i] == '\\')
        {
            num = i + 1;
            break;
        }
    }
    char* chTemp = &(strProcessName.Buffer[num]);
    KdPrint(("strProcessName.Buffer:%s\n", strProcessName.Buffer));
    KdPrint(("chTemp:%s - num = %d\n", chTemp, num));
    RtlStringCbCatNA(ProcessName, 256, &(strProcessName.Buffer[num]), num);
    RtlFreeAnsiString(&strProcessName);
    KdPrint(("ProcessName:%s\n", ProcessName));
}

void GetProcessPath(ULONG eprocess,CHAR ProcessPath[256])
{
    ULONG object;
    PFILE_OBJECT FilePointer;
    
    if(MmIsAddressValid((PULONG)(eprocess+0x138)))//Eprocess->sectionobject(0x138)
    {
        object=(*(PULONG)(eprocess+0x138));
        KdPrint(("[GetProcessFileName] sectionobject :0x%x\n",object));
        if(MmIsAddressValid((PULONG)((ULONG)object+0x014)))
        {
            object=*(PULONG)((ULONG)object+0x014);
            KdPrint(("[GetProcessFileName] Segment :0x%x\n",object));
            if(MmIsAddressValid((PULONG)((ULONG)object+0x0)))
            {
                object=*(PULONG)((ULONG_PTR)object+0x0);
                KdPrint(("[GetProcessFileName] ControlAera :0x%x\n",object));
                if(MmIsAddressValid((PULONG)((ULONG)object+0x024)))
                {
                    object=*(PULONG)((ULONG)object+0x024);
                    KdPrint(("[GetProcessFileName] FilePointer :0x%x\n",object));
                }
                else
                    return ;
            }
            else
                return ;
        }
        else
            return ;
    }
    else
        return ;

    KdPrint(("[GetProcessFileName] FilePointer :%wZ\n",&FilePointer->FileName));
}
```

## 三、GDT表Hook

### 1、FS寄存器

     用户层和内核层的FS寄存器的值是不同的，R3层FS寄存器指向TEB，R0层FS寄存器指向的是KPCR，处理器控制块，原因是

　　在R0和R3时，FS段寄存器分别指向GDT中的不同段:在R3下，FS段寄存器的值是0x3B，在R0下，FS段寄存器的值是0x30。


　　在 KiFastCallEntry / KiSystemService中FS值由0x3B变成0x30

　　在 KiSystemCallExit / KiSystemCallExitBranch / KiSystemCallExit2 中再将R3的FS恢复

　　Ring3与Ring0之间FS的转换，看下面的SystemService的实现
```cpp
nt!KiSystemService:
808696a1 6a00 push 0
808696a3 55 push ebp
808696a4 53 push ebx
808696a5 56 push esi
808696a6 57 push edi
808696a7 0fa0 push fs ;旧的R3 下的FS 保存入栈 
808696a9 bb30000000 mov ebx,30h
808696ae 668ee3 mov fs,bx ;FS=0X30 FS 值变成了0X30. 
808696b1 64ff3500000000 push dword ptr fs:[0]
808696b8 64c70500000000ffffffff mov dword ptr fs:[0],0FFFFFFFFh
808696c3 648b3524010000 mov esi,dword ptr fs:[124h] ;ESI=_ETHEAD
808696ca ffb640010000 push dword ptr [esi+140h] ;PreviousMode
808696d0 83ec48 sub esp,48h 
808696d3 8b5c246c mov ebx,dword ptr [esp+6Ch]
```
　　下面是KiSystemCallExit的部分代码，将fs还原成ring3层的值
```cpp
80869945 8d6550 lea esp,[ebp+50h]
80869948 0fa1 pop fs  ;恢复 FS 值 
8086994a 8d6554 lea esp,[ebp+54h]
8086994d 5f pop edi
8086994e 5e pop esi
8086994f 5b pop ebx
80869950 5d pop ebp
80869951 66817c24088000 cmp word ptr [esp+8],80h
```
　　当线程运行在R3下时，FS指向的段是GDT中的0x3B段。该段的长度为4K，基地址为当前线程的线程环境块（TEB），所以该段也被称为“TEB段”。因为Windows中线程是不停切换的，所以该段的基地址值将随线程切换而改变的。

　　Windows2000中进程环境块（PEB）的地址为0X7FFDF000，该进程的第一个线程的TEB地址为0X7FFDE000，第二个TEB的地址为0X7FFDD000…。。但是在WindowsXP SP3 下这些结构的地址都是随机映射的。所以进程的PEB的地址只能通过FS:[0x30]来获取了。

　　Windows中每个线程都有一个ETHREAD结构，该结构的TEB成员（其实是KTHREAD中的成员，而KTHREAD又是ETHREAD的成员）是用来保存线程的TEB地址的，当线程切换时，Windows就会用该值来更改GDT的0x30段描述符的基地址值。

　　

### 2.GDT结构

　　FS寄存器是16位寄存器，我们看一下每一位的意义

　　0和1位:代表当前特权级，用户层:11     内核层：00:：

　　2位：表指示位，0 表示在GDT(全局)中 ,1表示在LDT(局部)中：

　　3--15位：段索引。

　　在R0时，FS的值为0x30 ,二进制为 110 0 00 ， 00表示在内核层，0表示GDT，110表示段索引为6

　　下面我们用windbg测试一下
```cpp
kd> !pcr 0
KPCR for Processor 0 at ffdff000:
    Major 1 Minor 1
    NtTib.ExceptionList: 8054a4d0
        NtTib.StackBase: 8054acf0
       NtTib.StackLimit: 80547f00
     NtTib.SubSystemTib: 00000000
          NtTib.Version: 00000000
      NtTib.UserPointer: 00000000
          NtTib.SelfTib: 00000000
                SelfPcr: ffdff000
                   Prcb: ffdff120
                   Irql: 00000000
                    IRR: 00000000
                    IDR: ffffffff
          InterruptMode: 00000000
                    IDT: 8003f400
                    GDT: 8003f000
                    TSS: 80042000

          CurrentThread: 80553740
             NextThread: 00000000
             IdleThread: 80553740

              DpcQueue: 
```
　　我们用!pcr 0指令得到处理器块kpcr的地址为ffdff000，在这个结构体中我们可以获得IDT地址为8003f400和GDT的地址为8003f000

　　再看看索引值为6的地址为0x8003f030
```cpp
kd> dd 8003f000
8003f000 00000000 00000000 0000ffff 00cf9b00
8003f010 0000ffff 00cf9300 0000ffff 00cffb00
8003f020 0000ffff 00cff300 200020ab 80008b04
8003f030 f0000001 ffc093df
```
　　kd> db 8003f030 

　　8003f030 01 00 00 f0 df 93 c0 ff
```cpp
typedef struct _KGDTENTRY                 // 3 elements, 0x8 bytes (sizeof)  
{                                                                            
    /*0x000*/     UINT16       LimitLow;                 //0001                                     
    /*0x002*/     UINT16       BaseLow;                 //f000                                 
    union                                 // 2 elements, 0x4 bytes (sizeof)  
    {                                                                        
        struct                            // 4 elements, 0x4 bytes (sizeof)  
        {                                                                    
    　　　　　/*0x004*/             UINT8        BaseMid;                //df                            
            /*0x005*/             UINT8        Flags1;                    //93                     
            /*0x006*/             UINT8        Flags2;                    //c0                   
            /*0x007*/             UINT8        BaseHi;                   //ff                    
        }Bytes;                                                              
 
        struct                            // 10 elements, 0x4 bytes (sizeof) 
        {                                                                    
            /*0x004*/             ULONG32      BaseMid : 8;     // 0 BitPosition       //0xdf              
            /*0x004*/             ULONG32      Type : 5;        // 8 BitPosition                   
            /*0x004*/             ULONG32      Dpl : 2;         // 13 BitPosition                  
            /*0x004*/             ULONG32      Pres : 1;        // 15 BitPosition                  
            /*0x004*/             ULONG32      LimitHi : 4;     // 16 BitPosition                  
            /*0x004*/             ULONG32      Sys : 1;         // 20 BitPosition                  
            /*0x004*/             ULONG32      Reserved_0 : 1;  // 21 BitPosition                  
            /*0x004*/             ULONG32      Default_Big : 1; // 22 BitPosition                  
            /*0x004*/             ULONG32      Granularity : 1; // 23 BitPosition                  
            /*0x004*/             ULONG32      BaseHi : 8;      // 24 BitPosition              //0xff    
        }Bits;                                                               
    }HighWord;                                                               
}
}KGDTENTRY, *PKGDTENTRY;
```
　　对照着这个GDTENTRY的结构

　　kd> db 8003f030 

　　8003f030 01 00 00 f0 df 93 c0 ff

　　我们可以得到

　　BaseLow = 0xf000 ， BaseMid = 0xdf ， BaseHi = 0xff，于是就得到了一个地址 0xffdff000 。

　　这就是我们得到的KPCR的地址，就是FS为0x30在GDT中指向的地址。

　　再看看我们在IDT中的IDTEntry结构
```cpp
#pragma pack(1)
typedef struct
{
    WORD LowOffset;           //入口的低半地址
    WORD selector;
    BYTE unused_lo;
    unsigned char unused_hi:5;     // stored TYPE ?
    unsigned char DPL:2;
    unsigned char P:1;         // vector is present
    WORD HiOffset;          //入口地址的低半地址
} IDTENTRY;
#pragma pack()
```
　　其中的selector也是一个段选择符，IDT中例程函数的地址Target = 由LowOffset和HiOffset得到的地址+selector在GDT中指向的地址Base。

　　我们根据得到的IDT地址
```cpp
kd> dd 8003f400      =>IDT
8003f400 0008f19c 80538e00 0008f314 80538e00
8003f410 0058113e 00008500 0008f6e4 8053ee00 //我们的KiTrap03 8053f6e4
kd> db 8003f418
8003f418 e4 f6 08 00 00 ee 53 80
```
　　得到selector为0x8 = 1 0 00 ，表示R0层，GDT表中，索引为1
```cpp
kd> db 8003f008      =>GDT 
8003f008 ff ff 00 00 00 9b cf 00
```
　　可以得出 BaseLow =  0 , BaseMid = 0 , BaseHi = 0 ,得出的Base = 0;

　　所以真的执行的例程地址就是我们8053e8f6e4 （KiTrap03）。

 

### 3.Hook GDT

　　因为中断例程函数要依据GDT表，我们可以通过改变selector指向GDT的不同表项，GDT对应的表项中存放NewKiTrap03-KiTrap03，这样，我们就可以不改变IDT中的

　　KiTrap03而Hook IDT。
```cpp
 __asm 
  {
      sidt  idt_info            
      push edx
      sgdt [esp-2]
      pop edx
      mov GDT_Addr,edx
  }
  idt_entries = (IDTENTRY*) MAKELONG(idt_info.IDT_LOWbase,idt_info.IDT_HIGbase);
  g_OrigKiTrap03 = MAKELONG(idt_entries[3].LowOffset,idt_entries[3].HiOffset);
  jmpoffset    =    (ULONG)NewKiTrap03 - g_OrigKiTrap03;
  selector = idt_entries[1].selector;  //原来是8
  
  NewGDTAddr = GDT_Addr + 0x13;  //这里选择的索引为0x13的，空白的GDT表项
  //保存原来的 
  memcpy((UCHAR*)&OldBase,(char*)(&(NewGDTAddr->BaseLow)),2); 
  memcpy((UCHAR*)&OldBase+2,(char*)(&(NewGDTAddr->HighWord.Bytes.BaseMid)),1); 
  memcpy((UCHAR*)&OldBase+3,(char*)(&(NewGDTAddr->HighWord.Bytes.BaseHi)),1); 

  __asm cli;
  memcpy((char*)(&(NewGDTAddr->BaseLow)),(UCHAR*)&jmpoffset,2); 
  memcpy((char*)(&(NewGDTAddr->HighWord.Bytes.BaseMid)),(UCHAR*)(&jmpoffset)+2,1); 
  memcpy((char*)(&(NewGDTAddr->HighWord.Bytes.BaseHi)),(UCHAR*)(&jmpoffset)+3,1);
  OldSelector = idt_entries[3].selector; idt_entries[3].selector = 0x98; 
                                                       //10011 0 00 R0,GDT,0x13  
  __asm sti;
```