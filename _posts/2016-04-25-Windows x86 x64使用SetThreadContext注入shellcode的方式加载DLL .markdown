---
layout: post
title: Windows x86 x64使用SetThreadContext注入shellcode的方式加载DLL
date: 2016-04-25 20:33:12 +0900
category: Inject
---
## 一、前言
　　注入DLL的方式有很多，在R3就有远程线程CreateRemoteThread、SetWindowsHookEx、QueueUserApc、SetThreadContext

　　在R0可以使用apc或者使用KeUserModeCallBack

　　关于本文是在32位和64位下使用SetThreadContext注入DLL，32位下注入shellcode加载dll参考 创建进程时注入DLL，64位下shellcode通过编写asm汇编文件，使用windbg的attach调试获得。

## 二、编程思路

　　我们先打开目标进程，枚举目标线程采用的是系统快照的方式，比较线程所属的进程是否是我们的目标进程，SuspendThread挂起线程，GetThreadContext获得eip/rip，在目标进程空间写入Shellcode，SetThreadContext将eip/rip设置为我们shellcode的地址，shellcode执行load dll的工作，最后跳转回之前的eip继续执行。

#### 1、32位下shellcode
```cpp
BYTE ShellCode[64]=
{
    0x60,
    0x9c,
    0x68,               //push
    0xaa,0xbb,0xcc,0xdd,//dll path  +3  dll最目标进程中的地址
    0xff,0x15,          //call     这里感觉有点乱，我在64下直接call 相对地址 
    0xdd,0xcc,0xbb,0xaa,//+9 LoadLibrary Addr  Addr
    0x9d,
    0x61,
    0xff,0x25,          //jmp
    0xaa,0xbb,0xcc,0xdd,// +17  jmp  eip
    0xaa,0xaa,0xaa,0xaa,// loadlibrary addr
    0xaa,0xaa,0xaa,0xaa//  jmpaddr  +25

    //  +29
}; 
```
　　我们在代码中对于shellcode中填充内容，这样避免shellcode重定位的问题
```cpp
    strcpy((char*)DllPath,"D:\\Dllx86.dll");//这里是要注入的DLL名字
    *(DWORD*)(ShellCode+3)=(DWORD)LpAddr+29;
    ////////////////
    *(DWORD*)(ShellCode+21)=LoadDllAAddr;   //loadlibrary地址放入shellcode中
    *(DWORD*)(ShellCode+9)=(DWORD)LpAddr+21;//修改call 之后的地址 为目标空间存放 loaddlladdr的地址
    //////////////////////////////////
    *(DWORD*)(ShellCode+25)=ctx.Eip;
    *(DWORD*)(ShellCode+17)=(DWORD)LpAddr+25;//修改jmp 之后为原来eip的地址
```
　　最后翻译成汇编
```cpp
/*
{
00973689 >    60                PUSHAD
0097368A      9C                PUSHFD
0097368B      68 50369700       PUSH notepad.00973650
00973690      FF15 70369700     CALL DWORD PTR DS:[973670]
00973696      9D                POPFD
00973697      61                POPAD
00973698    - FF25 30369700     JMP DWORD PTR DS:[973630]
}
*/
```
　　然后需要注意的是 操作之前要 挂起， 结束后一定要 恢复，32位比较简单

 

#### 2.64位下的shellcode
```cpp
BYTE ShellCode64[64]=
{
    0x48,0x83,0xEC,0x28,  // sub rsp ,28h

    0x48,0x8D,0x0d,       // [+4] lea rcx,
    0xaa,0xbb,0xcc,0xdd,  // [+7] dll path offset =  TargetAddress- Current(0x48)[+4] -7 

    0x48, 0xB8,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xff, 0xd0,

    0x48,0x83,0xc4,0x28,  // [+16] add rsp,28h
    //0xcc, 调试时断下来的int 3 正常运行的时候非常傻逼的没有请掉...难怪一直死
    0xff,0x25,            // [+20]
    0xaa,0xbb,0xcc,0xdd,  // [+22] jmp rip offset  = TargetAddress - Current(0xff)[+20] - 6

    0xaa,0xbb,0xcc,0xdd,  //+26
    0xaa,0xbb,0xcc,0xdd   
    //+34
};
```
　　64位下，寻址都是相对寻址，函数调用参数传递是rcx，rdx，r8，r9，超过4参数采用栈传递

　　首先需要sub rsp,28h，为5*8 = 28h ，4个寄存器+返回地址

　　然后将dll名称地址给rcx 

　　在调用loadlibrary，最后跳回rip

```cpp
    DllPath=ShellCode64+41;
    strcpy((char*)DllPath,"Dllx64.dll");//这里是要注入的DLL名字
    DWORD DllNameOffset = 30;// ((BYTE*)LpAddr+34) -((BYTE*)LpAddr+4) -7 这个指令7个字节
    *(DWORD*)(ShellCode64+7)=(DWORD)DllNameOffset;
    ////////////////
    DWORD64 LoadDllAddroffset = (DWORD64)LoadDllAAddr;// - ((BYTE*)LpAddr + 11) -5;  //这个指令5个字节e8 + 4addroffset
    *(DWORD64*)(ShellCode64+13)=LoadDllAddroffset;
    //////////////////////////////////
    
    
    *(DWORD64*)(ShellCode64+33)=ctx.Rip; //64下为rip
    *(DWORD*)(ShellCode64+29)= (DWORD)0; //我将地址放在+29的地方，相对offset为0
```

## 三、完整代码
```cpp
#include "stdafx.h"

#include <iostream>
using namespace std;
#include <windows.h>
#include "tlhelp32.h"
BYTE ShellCode[64]=
{
    0x60,
    0x9c,
    0x68,               //push
    0xaa,0xbb,0xcc,0xdd,//dll path  +3  dll最目标进程中的地址
    0xff,0x15,          //call     这里感觉有点乱，我在64下直接call 相对地址 
    0xdd,0xcc,0xbb,0xaa,//+9 LoadLibrary Addr  Addr
    0x9d,
    0x61,
    0xff,0x25,          //jmp
    0xaa,0xbb,0xcc,0xdd,// +17  jmp  eip
    0xaa,0xaa,0xaa,0xaa,// loadlibrary addr
    0xaa,0xaa,0xaa,0xaa//  jmpaddr  +25

    //  +29
}; 

/*
{
00973689 >    60                PUSHAD
0097368A      9C                PUSHFD
0097368B      68 50369700       PUSH notepad.00973650
00973690      FF15 70369700     CALL DWORD PTR DS:[973670]
00973696      9D                POPFD
00973697      61                POPAD
00973698    - FF25 30369700     JMP DWORD PTR DS:[973630]
}
*/
BYTE ShellCode64[64]=
{
　　0x48,0x83,0xEC,0x28, // sub rsp ,28h

　　0x48,0x8D,0x0d, // [+4] lea rcx,
　　0xaa,0xbb,0xcc,0xdd, // [+7] dll path offset = TargetAddress- Current(0x48)[+4] -7

　　0x48, 0xB8,
　　0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
　　0xff, 0xd0,

　　0x48,0x83,0xc4,0x28, // [+16] add rsp,28h
　　//0xcc, 调试时断下来的int 3 正常运行的时候非常傻逼的没有请掉...难怪一直死
　　0xff,0x25, // [+20]
　　0xaa,0xbb,0xcc,0xdd, // [+22] jmp rip offset = TargetAddress - Current(0xff)[+20] - 6

　　0xaa,0xbb,0xcc,0xdd, //+26
　　0xaa,0xbb,0xcc,0xdd
　　//+34
};


BOOL EnableDebugPriv() ;
BOOL StartHook(HANDLE hProcess,HANDLE hThread);

int _tmain(int argc, _TCHAR* argv[])
{

    EnableDebugPriv() ;
    int ProcessId = 0;
    cin>>ProcessId;

    HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS,NULL,ProcessId);

    // 定义线程信息结构  
    THREADENTRY32 te32 = {sizeof(THREADENTRY32)} ;  
    //创建系统线程快照  ss
    HANDLE hThreadSnap = CreateToolhelp32Snapshot ( TH32CS_SNAPTHREAD, 0 ) ;  
    if ( hThreadSnap == INVALID_HANDLE_VALUE )  
        return FALSE ;  

    // 循环枚举线程信息  
    if ( Thread32First ( hThreadSnap, &te32 ) )  
    {  
        do{  

            if(te32.th32OwnerProcessID == ProcessId)
            {
                HANDLE Thread = OpenThread(THREAD_ALL_ACCESS,NULL,te32.th32ThreadID);

                SuspendThread(Thread);
                if (!StartHook(Process,Thread))
                {
                    TerminateProcess(Process,0);
                    printf("失败\n");
                    getchar();
                    return 0;
                }
                CloseHandle(Process);
                CloseHandle(Thread);


            }
            
        }while ( Thread32Next ( hThreadSnap, &te32 ) ) ;  
    }  

    CloseHandle ( hThreadSnap ) ;  
}





BYTE *DllPath;
BOOL StartHook(HANDLE hProcess,HANDLE hThread)
{

#ifdef _WIN64 

    CONTEXT ctx;
    ctx.ContextFlags=CONTEXT_ALL;
    if (!GetThreadContext(hThread,&ctx))
    {
        printf("GetThreadContext Error\n");
        return FALSE;
    }
    LPVOID LpAddr=VirtualAllocEx(hProcess,NULL,64,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if (LpAddr==NULL)
    {
        printf("VirtualAlloc Error\n");
        return FALSE;
    }
    DWORD64 LoadDllAAddr=(DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryA");
    if (LoadDllAAddr==NULL)
    {
        printf("LoadDllAddr error\n");
        return FALSE;
    }
    /*

    0x48,0x83,0xEC,0x28,  //sub rsp ,28h

    0x48,0x8D,0x0d,       // [+4] lea rcx,
    0xaa,0xbb,0xcc,0xdd,  // [+7] dll path offset =  TargetAddress- Current(0x48)[+4] -7 


    0xe8,                 // [+11]
    0xdd,0xcc,0xbb,0xaa,  // [+12] call LoadLibrary offset = TargetAddress - Current(0xe8)[+11] -5

    0x48,0x83,0xc4,0x28,  // [+16] add rsp,28h

    0xff,0x25,            // [+20]
    0xaa,0xbb,0xcc,0xdd,  // [+22] jmp rip offset  = TargetAddress - Current(0xff)[+20] - 6

    0xaa,0xbb,0xcc,0xdd,  //+26
    0xaa,0xbb,0xcc,0xdd   
    //+34
    */
　　DllPath=ShellCode64+41;
　　strcpy((char*)DllPath,"Dllx64.dll");//这里是要注入的DLL名字
　　DWORD DllNameOffset = 30;// ((BYTE*)LpAddr+34) -((BYTE*)LpAddr+4) -7 这个指令7个字节
　　*(DWORD*)(ShellCode64+7)=(DWORD)DllNameOffset;
　　////////////////
　　DWORD64 LoadDllAddroffset = (DWORD64)LoadDllAAddr;// - ((BYTE*)LpAddr + 11) -5; //这个指令5个字节e8 + 4addroffset
　　*(DWORD64*)(ShellCode64+13)=LoadDllAddroffset;
　　//////////////////////////////////


　　*(DWORD64*)(ShellCode64+33)=ctx.Rip; //64下为rip
　　*(DWORD*)(ShellCode64+29)= (DWORD)0; //我将地址放在+29的地方，相对offset为0

//  这里因为这样写跳转不到目标地址，故x64 应该要中转一次  相对寻址
//     DWORD Ds = (DWORD)ctx.SegDs;
//     DWORD RipOffset = (BYTE*)ctx.Rip - ((BYTE*)LpAddr+20) -6;
//     *(DWORD*)(ShellCode64+22)=(DWORD)ctx.Rip;

    ////////////////////////////////////
    if (!WriteProcessMemory(hProcess,LpAddr,ShellCode64,64,NULL))
    {
        printf("write Process Error\n");
        return FALSE;
    }
    ctx.Rip=(DWORD64)LpAddr;
    if (!SetThreadContext(hThread,&ctx))
    {
        printf("set thread context error\n");
        return FALSE;
    }
    ResumeThread(hThread);
    return TRUE;
    
#else
    CONTEXT ctx = {0};
    ctx.ContextFlags=CONTEXT_ALL;
    if (!GetThreadContext(hThread,&ctx))
    {
        int a = GetLastError();
        printf("GetThreadContext Error\n");
        return FALSE;
    }
    LPVOID LpAddr=VirtualAllocEx(hProcess,NULL,64,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if (LpAddr==NULL)
    {
        printf("VirtualAlloc Error\n");
        return FALSE;
    }
    DWORD LoadDllAAddr=(DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryA");
    if (LoadDllAAddr==NULL)
    {
        printf("LoadDllAddr error\n");
        return FALSE;
    }

    /////////////
    /*
    0x60,              PUSHAD
    0x9c,              PUSHFD
    0x68,              PUSH 
    0xaa,0xbb,0xcc,0xdd,//dll path  address  
    0xff,0x15,            CALL
    0xdd,0xcc,0xbb,0xaa,  offset  
    0x9d,                  POPFD
    0x61,                  POPAD
    0xff,0x25,             JMP 
    0xaa,0xbb,0xcc,0xdd,//  [xxxxx]
    0xaa,0xaa,0xaa,0xaa,// LoadLibrary Address
    0xaa,0xaa,0xaa,0xaa//  恢复的EIP  Address  
                         // +29  Dll名字
    */
    _asm mov esp,esp
    DllPath=ShellCode+29;
    strcpy((char*)DllPath,"D:\\Dllx86.dll");//这里是要注入的DLL名字
    *(DWORD*)(ShellCode+3)=(DWORD)LpAddr+29;
    ////////////////
    *(DWORD*)(ShellCode+21)=LoadDllAAddr;   //loadlibrary地址放入shellcode中
    *(DWORD*)(ShellCode+9)=(DWORD)LpAddr+21;//修改call 之后的地址 为目标空间存放 loaddlladdr的地址
    //////////////////////////////////
    *(DWORD*)(ShellCode+25)=ctx.Eip;
    *(DWORD*)(ShellCode+17)=(DWORD)LpAddr+25;//修改jmp 之后为原来eip的地址
    ////////////////////////////////////
    if (!WriteProcessMemory(hProcess,LpAddr,ShellCode,64,NULL))
    {
        printf("write Process Error\n");
        return FALSE;
    }
    ctx.Eip=(DWORD)LpAddr;
    if (!SetThreadContext(hThread,&ctx))
    {
        printf("set thread context error\n");
        return FALSE;
    }
    ResumeThread(hThread);
    return TRUE;
#endif
    
};




BOOL EnableDebugPriv() 
{
    HANDLE   hToken; 
    LUID   sedebugnameValue; 
    TOKEN_PRIVILEGES   tkp;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken)) 
    { 
        return   FALSE; 
    } 

    if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&sedebugnameValue)) 
    { 
        CloseHandle(hToken); 
        return   FALSE; 
    } 
    tkp.PrivilegeCount   =   1; 
    tkp.Privileges[0].Luid   =   sedebugnameValue; 
    tkp.Privileges[0].Attributes   =   SE_PRIVILEGE_ENABLED; 

    if(!AdjustTokenPrivileges(hToken,FALSE,&tkp,sizeof(tkp),NULL,NULL)) 
    { 
        return   FALSE; 
    }   
    CloseHandle(hToken); 
    return TRUE;

} 
```
## 四、64位Shellcode的编写过程
#### 1.编写内联汇编

```cpp
IncludeLib User32.Lib
;导入定义
EXTERN LoadLibraryA:PROC

;初始化数据定义
.DATA
szPath     BYTE  "D:\\Dll.dll",0

.CODE
  FUNC PROC 
  sub rsp,28H     ;分配堆栈,四个参数+返回值,十进制40(5*8)为16进制28H
  lea rcx,szPath  ;消息文本 
  call LoadLibraryA ;调用消息函数
  add rsp,28H      ;平衡堆栈,四个参数+返回值,十进制40为16进制28H 
  ret
  FUNC ENDP
 END
```
```cpp
// HelloPE.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<windows.h>

extern "C" int _cdecl FUNC();

int _tmain(int argc, _TCHAR* argv[])
{
    
    //LoadLibraryA("D:\\Dll.dll");
    int a  = 3;
    int b  = 4;
    int c = FUNC();
    printf("%d",c);
    return 0;
}
```
#### 2.使用Windbg中Attach到程序，查看对应的机器码
```cpp
HelloPE!FUNC:
00000001`3f5a1090 4883ec28        sub     rsp,28h
00000001`3f5a1094 488d0d877f0000  lea     rcx,[HelloPE!szPath (00000001`3f5a9022)]
00000001`3f5a109b e80a000000      call    HelloPE!LoadLibraryA (00000001`3f5a10aa)
00000001`3f5a10a0 4883c428        add     rsp,28h
00000001`3f5a10a4 c3              ret
00000001`3f5a10a5 cc              int     3
00000001`3f5a10a6 cc              int     3
00000001`3f5a10a7 cc              int     3
00000001`3f5a10a8 cc              int     3
00000001`3f5a10a9 cc              int     3


HelloPE!LoadLibraryA:
00000001`3f5a10aa ff25d8a20000    jmp     qword ptr [HelloPE!_imp_LoadLibraryA (00000001`3f5ab388)]
```
#### 3.根据字节码，编写shellcode
```cpp
BYTE ShellCode64[64]=
{
    0x48,0x83,0xEC,0x28,  // sub rsp ,28h

    0x48,0x8D,0x0d,       // [+4] lea rcx,
    0xaa,0xbb,0xcc,0xdd,  // [+7] dll path offset =  TargetAddress- Current(0x48)[+4] -7 

    0xe8,                 // [+11]
    0xdd,0xcc,0xbb,0xaa,  // [+12] call LoadLibrary offset = TargetAddress - Current(0xe8)[+11] -5

    0x48,0x83,0xc4,0x28,  // [+16] add rsp,28h
    //0xcc, 调试时断下来的int 3 正常运行的时候非常傻逼的没有清掉...难怪一直死
    0xff,0x25,            // [+20]
    0xaa,0xbb,0xcc,0xdd,  // [+22] jmp rip offset  = TargetAddress - Current(0xff)[+20] - 6

    0xaa,0xbb,0xcc,0xdd,  //+26
    0xaa,0xbb,0xcc,0xdd   
    //+34
};
```
代码下载 ：[InjectDllBySetThreadContextx64.zip](http://files.cnblogs.com/files/aliflycoris/InjectDllBySetThreadContextx64.zip)

