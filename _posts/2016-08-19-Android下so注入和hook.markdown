---
layout: post
title: Android下so注入和hook 
date: 2016-08-19 12:16:12 +0900
category: Android
---
## 一、前言

　　总结一下这两天学习的Android注入so文件，通过遍历got表hook函数调用

　　1.注入so文件

　　2.so文件中遍历got表hook函数

## 二、注入so文件

### 1)注入进程

　　1.编程思路分为以下几个步骤

　　①.每个进程都在/proc目录下，以进程id为文件夹名，所以可以通过/proc/<pid>/cmdline文件中中读取进程名称，和我们需要注入的进程名称比较，获得进程id

　　②.以root身份运行注入程序，通过ptrace函数，传入PTRACE_ATIACH附加到目标进程，PTRACE_SETREGS设置进程寄存器，PTRACE_GETREGS获得目标寄存器.更多可以访问ptrace的使用

　　③.调用mmap在对方进程空间分配内存，保存要加载的so文件路径，so中函数的名称，so中函数需要传入的参数。

　　由于每个模块在进程中加载地址不一致，所以我们首先获得目标进程中libc.so文件基址TargetBase，再获得自身libc.so基址SelfBase，再根据mmap-SelfBase+TargetBase获得目标进程中mmap的地址。

　　同理获得目标进程中dlopen()函数地址、dlsym()函数地址、dlclose()函数地址

　　④.调用dlopen()函数加载so库，调用dlsym()函数获得so库中函数的地址，调用so库中函数的地址，测试注入成功！调用dlclose()函数卸载so库。

　　

　　2.创建文件以及编码实现

　　首先创建一个jni目录，在jni下创建三个文件分别为inject.c、Android.mk、Application.mk。(注意：必须在jni目录下，否则编译报错)

　　jni

　　inject.c

　　Android.mk

　　Application.mk

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <android/log.h>
#include <elf.h>


#define ENABLE_DEBUG 1

#define PTRACE_PEEKTEXT 1
#define PTRACE_POKETEXT 4
#define PTRACE_ATTACH    16
#define PTRACE_CONT     7
#define PTRACE_DETACH   17
#define PTRACE_SYSCALL    24
#define CPSR_T_MASK        ( 1u << 5 )

#define  MAX_PATH 0x100

#define REMOTE_ADDR( addr, local_base, remote_base ) ( (uint32_t)(addr) + (uint32_t)(remote_base) - (uint32_t)(local_base) )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

#if defined(__i386__)
    #define pt_regs user_regs_struct
#endif

#if ENABLE_DEBUG
    #define LOG_TAG "INJECT"
    #define LOGD(fmt,args...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,fmt,##args)
    #define DEBUG_PRINT(format,args...) \
        LOGD(format, ##args)
#else
    #define DEBUG_PRINT(format,args...)
#endif


int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for ( i = 0; i < j; i ++ )
    {
         d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
         memcpy( laddr, d.chars, 4 );
         src += 4;
         laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, remain );
    }

    return 0;

}

int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size )
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;
    
    laddr = data;
    
    for ( i = 0; i < j; i ++ )
    {
        memcpy( d.chars, laddr, 4 );
        ptrace( PTRACE_POKETEXT, pid, dest, d.val );
    
        dest  += 4;
        laddr += 4;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, dest, 0 );
        for ( i = 0; i < remain; i ++ )
        {
            d.chars[i] = *laddr ++;
        }

        ptrace( PTRACE_POKETEXT, pid, dest, d.val );
        
    }

    return 0;
}


int ptrace_writestring( pid_t pid, uint8_t *dest, char *str  )
{
    return ptrace_writedata( pid, dest, str, strlen(str)+1 );
}

//在目标进程中执行指定函数
#if defined(__arm__)
int ptrace_call( pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs )
{
    uint32_t i;

    for ( i = 0; i < num_params && i < 4; i ++ )
    {
        regs->uregs[i] = params[i];
    }

    //
    // push remained params onto stack
    //
    if ( i < num_params )
    {
        //sp-4 ， 参数入栈
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata( pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long) );
    }
    //pc寄存器指向要call的地址
    regs->ARM_pc = addr;
    if ( regs->ARM_pc & 1 )
    {
        /*  thumb 
            判断最后一位，如果是1就是thumb指令集
                                0    arm指令集
        */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    }
    else
    {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }


    regs->ARM_lr = 0;    //目标进程执行完mmap之后暂停

    if ( ptrace_setregs( pid, regs ) == -1 
        || ptrace_continue( pid ) == -1 )
    {
        return -1;
    }

    //等待目标进程中mmap执行完成
    waitpid( pid, NULL, WUNTRACED );

    return 0;
}
#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long* params, uint32_t num_params, struct user_regs_struct* regs)
{
    regs->esp -= (num_params)*sizeof(long); /*开辟堆栈空间 存储参数*/
    ptrace_writedata(pid,(void*)regs->esp,(uint8_t*)params,(num_params)*sizeof(long));
    
    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid,regs->esp,(char*)&tmp_addr,sizeof(tmp_addr));
    
    regs->eip = addr;  //修改指令指针寄存器，指向要运行的函数
    
    if(ptrace_setregs(pid,regs)==-1 || ptrace_continue(pid) == -1) //恢复函数状态，函数入口处运行
    { 
        printf("error\n");
        return -1;
    }
    int stat = 0;
    waitpid(pid,&stat,WUNTRACED);
    while(stat!= 0xb7f)
    {
        if(ptrace_continue(pid)==-1)
        {
            printf("error\n");
            return -1;
        }
        waitpid(pid,&stat,WUNTRACED);
    }
    return 0;
        
}
#else
    #error "Not supported"
#endif
//获取目标进程寄存器
int ptrace_getregs( pid_t pid, struct pt_regs* regs )
{
    if ( ptrace( PTRACE_GETREGS, pid, NULL, regs ) < 0 )
    {
        perror( "ptrace_getregs: Can not get register values" );
        return -1;
    }

    return 0;
}

//设置目标进程寄存器
int ptrace_setregs( pid_t pid, struct pt_regs* regs )
{
    if ( ptrace( PTRACE_SETREGS, pid, NULL, regs ) < 0 )
    {
        perror( "ptrace_setregs: Can not set register values" );
        return -1;
    }

    return 0;
}




int ptrace_continue( pid_t pid )
{
    if ( ptrace( PTRACE_CONT, pid, NULL, 0 ) < 0 )
        {
            perror( "ptrace_cont" );
            return -1;
        }

        return 0;
}

//attach到目标进程ptrace_attach
int ptrace_attach( pid_t pid )
{
    if ( ptrace( PTRACE_ATTACH, pid, NULL, 0  ) < 0 )
    {
        perror( "ptrace_attach" );
        return -1;
    }

    //暂停目标进程
    waitpid( pid, NULL, WUNTRACED );

    //DEBUG_PRINT("attached\n");
    //做出系统调用或者准备退出的时候暂停
    if ( ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0 )
    {
        perror( "ptrace_syscall" );
        return -1;
    }


    //子进程暂停之后立即返回
    waitpid( pid, NULL, WUNTRACED );

    return 0;
}

int ptrace_detach( pid_t pid )
{
    if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
        {
            perror( "ptrace_detach" );
            return -1;
        }

        return 0;
}

void* get_module_base( pid_t pid, const char* module_name )
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if ( pid < 0 )
    {
        /* self process */
        snprintf( filename, sizeof(filename), "/proc/self/maps", pid );
    }
    else
    {
        snprintf( filename, sizeof(filename), "/proc/%d/maps", pid );
    }

    fp = fopen( filename, "r" );

    if ( fp != NULL )
    {
        while ( fgets( line, sizeof(line), fp ) )
        {
            if ( strstr( line, module_name ) )
            {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if ( addr == 0x8000 )
                    addr = 0;

                break;
            }
        }

                fclose( fp ) ;
    }

    return (void *)addr;
}

//获取函数在目标进程中的地址
void* get_remote_addr( pid_t target_pid, const char* module_name, void* local_addr )
{
    void* local_handle, *remote_handle;
    //指定模块在我们自己进程中的基地址
    local_handle = get_module_base( -1, module_name );
    //指定模块在目标进程中的基地址
    remote_handle = get_module_base( target_pid, module_name );

    DEBUG_PRINT( "[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle );
    //mmap函数在目标进程的绝对地址
    void* ret_addr = (void *)( (uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle );
    
#if defined(__i386__)
    if(!strcmp(module_name,libc_path)){
        ret_addr += 2;
    }
#endif
    return ret_addr;    
}

//读取/proc目录下以id为文件夹名的文件夹内cmdline的内容
int find_pid_of( const char *process_name )
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if ( process_name == NULL )
        return -1;

    dir = opendir( "/proc" );
    if ( dir == NULL )
        return -1;

    while( (entry = readdir( dir )) != NULL )
    {
        id = atoi( entry->d_name );
        if ( id != 0 )
        {
            sprintf( filename, "/proc/%d/cmdline", id );
            fp = fopen( filename, "r" );
            if ( fp )
            {
                fgets( cmdline, sizeof(cmdline), fp );
                fclose( fp );

                if ( strcmp( process_name, cmdline ) == 0 )
                {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir( dir );

    return pid;
}

long ptrace_retval(struct pt_regs* regs)
{
#if defined(__arm__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}

long ptrace_ip(struct pt_regs* regs)
{
#if defined(__arm__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

int ptrace_call_wrapper(pid_t target_pid, const char* func_name, void* func_addr, long* parameters,int param_num,struct pt_regs* regs)
{
    DEBUG_PRINT("[+]Calling%s in target process.\n",func_name);
    if(ptrace_call(target_pid,(uint32_t)func_addr,parameters,param_num,regs)==-1)  //修改eip，运行函数
        return -1;
    if(ptrace_getregs(target_pid,regs)==-1)
        return -1;
    DEBUG_PRINT("[+]Target process returned from%s,return value = %x,pc=%x\n",func_name,ptrace_retval(regs),ptrace_ip(regs));
    return 0;
}
int inject_remote_process( pid_t target_pid, const char *library_path, const char *func_name, void *param, size_t param_size )
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr,*dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
            _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
            _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;


    long parameters[10];



    DEBUG_PRINT( "[+] Injecting process: %d\n", target_pid );

    /*attach到指定进程*/
    if ( ptrace_attach( target_pid ) == -1 )
        return EXIT_SUCCESS;

    /*获得进程寄存器*/
    if ( ptrace_getregs( target_pid, &regs ) == -1 )
        goto exit;

    /*保存进程寄存器值*/
    memcpy( &original_regs, &regs, sizeof(regs) );

    /*通过自己进程中mmap函数相对与libc.so基址的偏移，在目标进程中通过libc.so基址获得mmap地址*/
    mmap_addr = get_remote_addr( target_pid, "/system/lib/libc.so", (void *)mmap );

    DEBUG_PRINT( "[+] Remote mmap address: %x\n", mmap_addr );

    /* 调用mmap分配内存空间 */
    parameters[0] = 0;    // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    DEBUG_PRINT( "[+] Calling mmap in target process.\n" );

    if(ptrace_call_wrapper(target_pid,"mmap",mmap_addr,parameters,6,&regs)==-1)  //调用mmap在目标进程中分配内存空间
        goto exit;


    map_base = ptrace_retval(&regs);  //取回分配的地址
    DEBUG_PRINT("mmap_base is %x",map_base);
    
    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen ); //获得目标进程中dlopen函数地址
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym ); //获得目标进程中dlsym函数地址
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );//获得目标进程中dlclose函数地址
    dlerror_addr = get_remote_addr(target_pid,linker_path,(void *)dlerror); //获得目标进程中dlerror函数地址
    DEBUG_PRINT( "[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x,dlerror: %x\n", dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    printf("library path = %s\n",library_path);
    ptrace_writedata(target_pid,map_base,library_path,strlen(library_path)+1); //在目标进程分配的空间中，写入要加载的动态库路径
    
    parameters[0] = map_base;
    parameters[1] = RTLD_NOW|RTLD_GLOBAL;
    
    if(ptrace_call_wrapper(target_pid,"dlopen",dlopen_addr,parameters,2,&regs)==-1) //调用dlopen函数，加载动态库
        goto exit;
    
    
    
    void* sohandle = ptrace_retval(&regs); //返回加载动态库句柄
#define FUNCTION_NAME_ADDR_OFFSET 0x100
    ptrace_writedata(target_pid,map_base+FUNCTION_NAME_ADDR_OFFSET,func_name,strlen(func_name)+1); //将动态库中函数hook_entry的名称写入 分配地址+0x100的地方
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;
    
    if(ptrace_call_wrapper(target_pid,"dlsym",dlsym_addr,parameters,2,&regs)==-1) //调用dlsym，获得动态库中hook_entry的地址
        goto exit;
    
    void* hook_entry_addr = ptrace_retval(&regs); //获得hook_entry函数的地址
    DEBUG_PRINT("hook_entry_addr = %p\n",hook_entry_addr);
    
#define FUNCTION_PARAM_ADDR_OFFSET 0x200
    ptrace_writedata(target_pid,map_base+FUNCTION_PARAM_ADDR_OFFSET,param,strlen(param)+1); //将传入参数 "I'm parameter!" 写入分配地址空间+0x200处
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;
    if(ptrace_call_wrapper(target_pid,"hook_entry",hook_entry_addr,parameters,1,&regs)==-1) //调用注入的动态库中hook_entry函数，传入参数"I'm parameter!" 
        goto exit;
    
    printf("Press enter to dlclose and detach\n"); //结束，等待
    getchar();
    parameters[0] = sohandle;
    
    if(ptrace_call_wrapper(target_pid,"dlclose",dlclose,parameters,1,&regs)==-1) //调用dlclose卸载动态库
        goto exit;
    
    ptrace_setregs(target_pid,&original_regs); //还原寄存器
    ptrace_detach(target_pid); //关闭
    ret = 0;

exit:
    return ret;
}
int main(int argc, char** argv) {
    pid_t target_pid;
    target_pid = find_pid_of("/system/bin/surfaceflinger");
    inject_remote_process( target_pid, "/data/libhello.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
}
```

　　使用ps命令可以查看进程列表，获取进程ID和路径，然后在main中输入进程的路径，注入进程

　　Android.mk：
```cpp
LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
LOCAL_MODULE := inject
LOCAL_SRC_FILES := inject.c
 
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
include $(BUILD_EXECUTABLE)
```
　　Application.mk
```cpp
APP_ABI := x86 armeabi-v7a
```
　　然后使用ndk-build命令编译生成可执行文件，一定要在jni目录下，不然编译会报错，记住 __android_log_print函数前面有两个下划线，在Android.mk中申明的库 LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

![1](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/1.png)

![2](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/2.png)

### 2)so文件测试Demo

　　我们创建so文件测试是否inject是否能注入成功，并调用so中函数

　　创建目录和文件

　　jni

　　hello.c

　　Android.mk

　　Application.mk

 

　　hello.c
```cpp
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <fcntl.h>

#define LOG_TAG "DEBUG"
#define LOGD(fmt,args...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,fmt,##args)

int hook_entry(char* a ){
    LOGD("Hook success,pid=%d\n",getpid());
    LOGD("Hello %s\n",a);  //调用传入的参数    "I'm parameter!"

        return 0; 
}
```
　　Android.mk

```cpp
LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog
LOCAL_MODULE :=hello
LOCAL_SRC_FILES:= hello.c
include $(BUILD_SHARED_LIBRARY)
```
　　Application.mk
```cpp
APP_ABI := x86 armeabi-v7a
```
　　使用ndk-build编译生成x86和arm平台下的so文件：

![3](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/3.png)

　　然后就可以执行，连接root过的Android或者Android虚拟机，将inject和so文件考入设备，设置执行权限，执行。

![4](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/4.png)

　　我们现在可以查看进程内存，另起一个cmd窗口 ，因为我们在文件中的Log标志为INJECT，所以我们先打印log

　　使用 adb logcat -s INJECT命令

![5](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/5.png)

　　可以看到我们注入的进程id为36，我们查看这个进程的内存中加载的模块

　　使用命令   cat /proc/36/maps

![6](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/6.png)

![7](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/7.png)

　　注入成功！

 

### 3)通过so文件实现got表Hook

　　1.编码思路

　　首先了解一下动态加载机制，

　　　　a、模块甲在编译期间，将要引用的模块乙的名字与函数名写入自身的符号表。
　　　　b、运行期模块甲调用时，调用流程是从调用代码到PLT表到GOT表再跳入模块乙。

　　也就是got表中保存着函数地址。

　　更多ELF文件了解可以参考：ELF文件格式解析

　　①首先保存系统中的函数地址，这里直接是调用函数的名称。

　　②获取函数所在模块基地址，通过遍历/proc/<pid>/maps文件

　　③遍历模块的got表，地址与保存的地址一致则hook，如果和fake函数一致则已经Hook过了。

              

　　修改的hello.c文件

```cpp
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>

#define LOG_TAG "DEBUG"
#define LOGD(fmt,args...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,fmt,##args)
EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy,EGLSurface surf) = -1;

EGLBoolean new_eglSwapBuffers(EGLDisplay dpy,EGLSurface surface)
{
    LOGD("New eglSwapBuffers");
    if(old_eglSwapBuffers==-1)
        LOGD("error\n");
    return old_eglSwapBuffers(dpy,surface);
}

void* get_module_base(pid_t pid,const char* module_name)
{
    FILE* fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];
    
    if(pid<0){
        snprintf(filename,sizeof(filename),"/proc/self/maps",pid);
    }else{
        snprintf(filename,sizeof(filename),"/proc/%d/maps",pid);
    }
    fp = fopen(filename,"r");
    if(fp!=NULL){
        while(fgets(line,sizeof(line),fp)){
            if(strstr(line,module_name)){
                pch = strtok(line,"-");
                addr = strtoul(pch,NULL,16);
                if(addr==0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }
    return (void*)addr;
}

#define LIBSF_PATH "/system/lib/libsurfaceflinger.so"
int hook_eglSwapBuffers()
{
    old_eglSwapBuffers = eglSwapBuffers;  //保存系统中原来eglSwapBuffers函数地址，在Android.mk中加入库
    LOGD("Orig eglSwapBuffers = %p\n",old_eglSwapBuffers);
    void* base_addr = get_module_base(getpid(),LIBSF_PATH); //动态库地址
    LOGD("libsurfaceflinger.so address = %p\n",base_addr);
    
    int fd;
    fd = open(LIBSF_PATH,O_RDONLY);
    if(fd==-1){
        LOGD("error\n");
        return -1;
    }
    Elf32_Ehdr ehdr;  //ELF header
    read(fd,&ehdr,sizeof(Elf32_Ehdr)); //读取ELF文件格式的文件头信息
    
    unsigned long shdr_addr = ehdr.e_shoff; //section header table文件中的偏移
    int shnum = ehdr.e_shnum; //section header table中有多少个条目
    int shent_size = ehdr.e_shentsize; //section header table每一个条目的大小
    unsigned long stridx = ehdr.e_shstrndx; //包含节名称的字符串是第几个节(从0开始)
    
    Elf32_Shdr shdr; //节头结构定义
    lseek(fd,shdr_addr+stridx*shent_size,SEEK_SET); //偏移到文件尾
    read(fd,&shdr,shent_size); //读取字符串表的信息
    
    char* string_table = (char*)malloc(shdr.sh_size);//分配内存
    lseek(fd,shdr.sh_offset,SEEK_SET);//偏移到字符串表
    
    read(fd,string_table,shdr.sh_size); //读取字符串表的内容
    
    
    lseek(fd,shdr_addr,SEEK_SET);//还原指针到section header table处
    
    int i;
    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;
    
    for(i = 0; i < shnum; i++){//每个节头信息,找到got表
        read(fd,&shdr,shent_size);
        if(shdr.sh_type == SHT_PROGBITS){
            int name_idx = shdr.sh_name;//名称索引
            if(strcmp(&(string_table[name_idx]),".got.plt")==0 || strcmp(&(string_table[name_idx]),".got")==0){
                out_addr = base_addr + shdr.sh_addr;//获得got表
                out_size = shdr.sh_size;
                LOGD("out_addr = %lx,out_size = %lx\n",out_addr,out_size);
                
                for(i=0;i<out_size;i+=4){
                    got_item = *(uint32_t*)(out_addr+i);
                    if(got_item == old_eglSwapBuffers){
                        LOGD("Found eglSwapBuffers in got\n");
                        got_found = 1;
                        //hook
                        uint32_t page_size = getpagesize();   
                        uint32_t entry_page_start = (out_addr + i)&(~(page_size-1));
                        mprotect((uint32_t*)entry_page_start,page_size,PROT_READ|PROT_WRITE);
                        *(uint32_t*)(out_addr + i) = new_eglSwapBuffers;
                        break;
                    }else if(got_item == new_eglSwapBuffers){
                        LOGD("Already hooked\n");
                        break;
                    }
                }
                if(got_found)
                    break;
            }
        }
    }
    free(string_table);
    close(fd);
}
int hook_entry(char* a ){
    LOGD("Hook success,pid=%d\n",getpid());
    LOGD("Hook information: %s\n",a);
    LOGD("Start hooking\n");
    hook_eglSwapBuffers();
    return 0;
}
```
　　Android.ml改为
```cpp
LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
 
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog -lEGL
LOCAL_MODULE :=hello
LOCAL_SRC_FILES:= hello.c
include $(BUILD_SHARED_LIBRARY)
```
　　Application.mk改为
```cpp
APP_ABI := x86 armeabi-v7a
APP_PLATFORM := android-14
```
　　运行ndk-build编译，和上面一样执行，我们可以看到log信息已经hook成功了

![8](https://raw.githubusercontent.com/LycorisGuard/BlogPic/master/2016-08-19/8.png)

## 三、总结

　　这里我们在/proc/pid/cmdline文件中比较进程名称，在/proc/pid/maps文件中查找进程模块，使用ptrace系列函数进行进程、寄存器操作，使用mmap函数在其他进程分配内存空间，使用dlopen获取so库地址，使用dlsym获取so库中函数地址，使用dlclose卸载so库，通过got表获取调用函数地址，通过mprotect更改保护属性。

　　一次不错的学习体验！

　　参考：

　　[Android中so的注入(inject)和挂钩(hook) - For both x86 and arm](http://www.360doc.com/content/14/0329/23/10366845_364806185.shtml)

　　[Android下通过root实现对system_server中binder的ioctl调用拦截](https://bbs.pediy.com/thread-157419.htm)
