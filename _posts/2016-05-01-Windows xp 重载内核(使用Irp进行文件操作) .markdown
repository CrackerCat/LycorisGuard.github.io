---
layout: post
title: Windows xp 重载内核(使用Irp进行文件操作)
date: 2016-05-01 09:45:12 +0900
category: windowsDriver
---
## 一、前言
　　最近在阅读A盾代码[A盾电脑防护（原名 3600safe）anti-rootkit开放源代码](https://bbs.pediy.com/thread-150599.htm)，有兴趣的可以去看雪论坛下载，本文代码摘自其中的重载内核。

## 二、实现步骤

　　1.ZwQuerySystemInformation大法获得系统模块信息 NtosKrnl.exe 这里第一模块名称是根据单核、多核、开启PAE、未开启PAE变化的

　　2.自己Reload一个内核模块，打开、获得文件大小、读入内存，这里都用到Irp的操作

　　irpSp->Parameters.MountVolume.Vpb->RealDevice卷设备

　　VPB是Volume parameter block一个数据结构，把实际存储媒介设备对象和文件系统上的卷设备对象联系起来。

　　利用Irp请求对文件进行操作是防止Hook一些文件读取、查询的函数，除非是Hook了IoCallDriver函数，不过也会对这个函数进行监测，具体可以看<寒江独钓><文件系统开发教程>(楚狂人 谭文)

　　3.将读入的内存按照内存中的位置放置。VirtualAglin = 0x1000对齐

　　4.根据DriverSection枚举内核模块，修复Reload的导入信息

　　5.修复重定位表信息

　　6.根据重定位表中的偏移比较获得 ， 在Reload中的SSDT地址的偏移

　　7.将Reload的SSDT函数地址写入我们的全局变量 SSDT中

　　8.MmGetSystemRoutine获得Reload中函数的地址

## 三、代码实现
### 1.获得模块信息

　　通过ZwQuerySystemInformation函数传入宏SystemModuleInformation，返回内核模块信息。

```cpp
/*ZwQuerySystemInformation大法 枚举模块信息  获得第一模块  Ntos..*/
BOOLEAN GetSystemKernelModuleInfo(WCHAR **SystemKernelModulePath,PDWORD SystemKernelModuleBase,PDWORD SystemKernelModuleSize)
{
    NTSTATUS status;
    ULONG ulSize,i;
    PMODULES pModuleList;
    char *lpszKernelName=NULL;
    ANSI_STRING AnsiKernelModule;
    UNICODE_STRING UnicodeKernelModule;
    BOOLEAN bRet=TRUE;

    __try
    {
        status=ZwQuerySystemInformation(
            SystemModuleInformation,
            NULL,
            0,
            &ulSize
            );
        if (status!=STATUS_INFO_LENGTH_MISMATCH)
        {
            return NULL;
        }
        pModuleList=(PMODULES)ExAllocatePool(NonPagedPool,ulSize);
        if (pModuleList)
        {
            status=ZwQuerySystemInformation(
                SystemModuleInformation,
                pModuleList,
                ulSize,
                &ulSize
                );
            if (!NT_SUCCESS(status))
            {
                bRet = FALSE;
            }
        }
        if (!bRet)
        {
            if (pModuleList)
                ExFreePool(pModuleList);
            return NULL;
        }
        *SystemKernelModulePath=ExAllocatePool(NonPagedPool,260*2);
        if (*SystemKernelModulePath==NULL)
        {
            *SystemKernelModuleBase=0;
            *SystemKernelModuleSize=0;
            return NULL;
        }

        lpszKernelName = pModuleList->smi[0].ModuleNameOffset+pModuleList->smi[0].ImageName;  //第一模块名称
        RtlInitAnsiString(&AnsiKernelModule,lpszKernelName);
        RtlAnsiStringToUnicodeString(&UnicodeKernelModule,&AnsiKernelModule,TRUE);

        RtlZeroMemory(*SystemKernelModulePath,260*2);
        wcscat(*SystemKernelModulePath,L"\\SystemRoot\\system32\\");

        memcpy(
            *SystemKernelModulePath+wcslen(L"\\SystemRoot\\system32\\"),    //第一模块路径
            UnicodeKernelModule.Buffer,
            UnicodeKernelModule.Length
            );

        *SystemKernelModuleBase=(DWORD)pModuleList->smi[0].Base;   //获得第一模块地址
        *SystemKernelModuleSize=(DWORD)pModuleList->smi[0].Size;   //获得第一模块大小
        ExFreePool(pModuleList);
        RtlFreeUnicodeString(&UnicodeKernelModule);

    }__except(EXCEPTION_EXECUTE_HANDLER){

    }
    return TRUE;
}
```
### 2.Reload Pe
```cpp
/*
system32//NtosKrnl.exe .. 
*/
BOOLEAN PeLoad(
    WCHAR *FileFullPath,
    BYTE **ImageModeleBase,
    PDRIVER_OBJECT DeviceObject,
    DWORD ExistImageBase
    )
{
    NTSTATUS Status;
    HANDLE hFile;
    LARGE_INTEGER FileSize;
    DWORD Length;
    BYTE *FileBuffer;
    BYTE *ImageBase;
    IO_STATUS_BLOCK IoStatus;
    //\SystemRoot\system32\ntkrnlpa.exe
    Status=KernelOpenFile(FileFullPath,&hFile,0x100020,0x80,1,1,0x20);  //自己创建文件对象， 并返回文件句柄，irp
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    Status=KernelGetFileSize(hFile,&FileSize);  //读取irp信息，返回filesize
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hFile);
        return FALSE;
    }
    Length=FileSize.LowPart;
    FileBuffer=ExAllocatePool(PagedPool,Length);
    if (FileBuffer==NULL)
    {
        ZwClose(hFile);
        return FALSE;
    }

    Status=KernelReadFile(hFile,NULL,Length,FileBuffer,&IoStatus); //传入文件句柄、文件大小 通过irp请求，读取文件到内存中
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hFile);
        ExFreePool(FileBuffer);
        return FALSE;
    }
    ZwClose(hFile);


    if(!ImageFile(FileBuffer,&ImageBase))   //修复FileBuffer中的偏移  按照VirtualAglin  对齐    得到全局ImageModuleBase
    {
        ExFreePool(FileBuffer);
        return FALSE;
    }
    ExFreePool(FileBuffer);

    //2k3下MiFindExportedRoutine调用失败
    if(!FixImportTable(ImageBase,ExistImageBase,DeviceObject)) //修复导入表
    {
        ExFreePool(ImageBase);
        return FALSE;
    }
    if(!FixBaseRelocTable(ImageBase,ExistImageBase))  //修复重定位表
    {
        ExFreePool(ImageBase);
        return FALSE;
    }

    *ImageModeleBase=ImageBase; //得到最后的基地址   就是 和 原来内存中格式一样的 一块ntos

    return TRUE;
}
```
### 3.按VirtualAglin对齐
```cpp
/*
修复FileBuffer中的偏移  按照VirtualAglin  对齐  
filebuffer 为读取的内存  ，ImageModuleBase为系统中的模块地址
*/
BOOLEAN ImageFile(BYTE *FileBuffer,BYTE **ImageModuleBase)
{
    PIMAGE_DOS_HEADER ImageDosHeader;
    PIMAGE_NT_HEADERS ImageNtHeaders;
    PIMAGE_SECTION_HEADER ImageSectionHeader;
    DWORD FileAlignment,SectionAlignment,NumberOfSections,SizeOfImage,SizeOfHeaders;
    DWORD Index;
    BYTE *ImageBase;
    DWORD SizeOfNtHeaders;
    ImageDosHeader=(PIMAGE_DOS_HEADER)FileBuffer;
    if (ImageDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }
    ImageNtHeaders=(PIMAGE_NT_HEADERS)(FileBuffer+ImageDosHeader->e_lfanew);
    if (ImageNtHeaders->Signature!=IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }
    FileAlignment=ImageNtHeaders->OptionalHeader.FileAlignment;//0x200
    SectionAlignment=ImageNtHeaders->OptionalHeader.SectionAlignment;//0x1000
    NumberOfSections=ImageNtHeaders->FileHeader.NumberOfSections;//0x16
    SizeOfImage=ImageNtHeaders->OptionalHeader.SizeOfImage;//0x412000
    SizeOfHeaders=ImageNtHeaders->OptionalHeader.SizeOfHeaders;//0x800

    SizeOfImage=AlignSize(SizeOfImage,SectionAlignment);//0x412000

    ImageBase=ExAllocatePool(NonPagedPool,SizeOfImage);
    if (ImageBase==NULL)
    {
        return FALSE;
    }
    RtlZeroMemory(ImageBase,SizeOfImage);
    //0xf8
    SizeOfNtHeaders=sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature)+ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
    ImageSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)ImageNtHeaders+SizeOfNtHeaders);
    for (Index=0;Index<NumberOfSections;Index++)
    {
        ImageSectionHeader[Index].SizeOfRawData=AlignSize(ImageSectionHeader[Index].SizeOfRawData,FileAlignment);
        ImageSectionHeader[Index].Misc.VirtualSize=AlignSize(ImageSectionHeader[Index].Misc.VirtualSize,SectionAlignment);
    }
    if (ImageSectionHeader[NumberOfSections-1].VirtualAddress+ImageSectionHeader[NumberOfSections-1].SizeOfRawData>SizeOfImage)
    {//no in
        ImageSectionHeader[NumberOfSections-1].SizeOfRawData = SizeOfImage-ImageSectionHeader[NumberOfSections-1].VirtualAddress;
    }
    RtlCopyMemory(ImageBase,FileBuffer,SizeOfHeaders);

    for (Index=0;Index<NumberOfSections;Index++)
    {
        DWORD FileOffset=ImageSectionHeader[Index].PointerToRawData;
        DWORD Length=ImageSectionHeader[Index].SizeOfRawData;
        DWORD ImageOffset=ImageSectionHeader[Index].VirtualAddress;
        RtlCopyMemory(&ImageBase[ImageOffset],&FileBuffer[FileOffset],Length);
    }
    *ImageModuleBase=ImageBase;

    return TRUE;


}

ULONG AlignSize(ULONG nSize, ULONG nAlign)
{
    return ((nSize + nAlign - 1) / nAlign * nAlign);
}
```
### 4.修复导入表，这里利用DriverObject->DriverSection遍历内核模块，找出导入表相等的模块，根据序号或者名称修复导入表
```cpp
//修复导入表
BOOLEAN FixImportTable(BYTE *ImageBase,DWORD ExistImageBase,PDRIVER_OBJECT DriverObject)
{
    PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor=NULL;
    PIMAGE_THUNK_DATA ImageThunkData,FirstThunk;
    PIMAGE_IMPORT_BY_NAME ImortByName;
    DWORD ImportSize;
    PVOID ModuleBase;
    char ModuleName[260];
    DWORD FunctionAddress;
    //得到导入表地址
    ImageImportDescriptor=(PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(ImageBase,TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT,&ImportSize);
    if (ImageImportDescriptor==NULL)
    {
        return FALSE;
    }
    while (ImageImportDescriptor->OriginalFirstThunk&&ImageImportDescriptor->Name)
    {
        strcpy(ModuleName,(char*)(ImageBase+ImageImportDescriptor->Name));  //导入信息名称

        //ntoskrnl.exe(NTKRNLPA.exe、ntkrnlmp.exe、ntkrpamp.exe)：
        if (_stricmp(ModuleName,"ntkrnlpa.exe")==0||
            _stricmp(ModuleName,"ntoskrnl.exe")==0||
            _stricmp(ModuleName,"ntkrnlmp.exe")==0||
            _stricmp(ModuleName,"ntkrpamp.exe")==0)
        {//no in
            ModuleBase=GetKernelModuleBase(DriverObject,"ntkrnlpa.exe");  //通过DriverObject->DriverSection 遍历内核模块
            if (ModuleBase==NULL)
            {
                ModuleBase=GetKernelModuleBase(DriverObject,"ntoskrnl.exe");
                if (ModuleBase==NULL)
                {
                    ModuleBase=GetKernelModuleBase(DriverObject,"ntkrnlmp.exe");
                    if (ModuleBase==NULL)
                    {
                        ModuleBase=GetKernelModuleBase(DriverObject,"ntkrpamp.exe");

                    }

                }
            }

        }
        else
        {
            ModuleBase=GetKernelModuleBase(DriverObject,ModuleName);

        }
        if (ModuleBase==NULL)
        {
            FirstThunk=(PIMAGE_THUNK_DATA)(ImageBase+ImageImportDescriptor->FirstThunk);
            InsertOriginalFirstThunk((DWORD)ImageBase,ExistImageBase,FirstThunk);
            ImageImportDescriptor++;
            continue;
        }
        //PSHED.dll
        ImageThunkData=(PIMAGE_THUNK_DATA)(ImageBase+ImageImportDescriptor->OriginalFirstThunk);
        FirstThunk=(PIMAGE_THUNK_DATA)(ImageBase+ImageImportDescriptor->FirstThunk);
        while(ImageThunkData->u1.Ordinal)
        {
            //序号导入
            if(IMAGE_SNAP_BY_ORDINAL32(ImageThunkData->u1.Ordinal))
            {
                //通过系统内核的导出表   名称- 获得 函数地址
                FunctionAddress=(DWORD)MiFindExportedRoutine(ModuleBase,FALSE,NULL,ImageThunkData->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
                if (FunctionAddress==0)
                {
                    return FALSE;
                }
                FirstThunk->u1.Function=FunctionAddress;
            }
            //函数名导入
            else
            {
                //
                ImortByName=(PIMAGE_IMPORT_BY_NAME)(ImageBase+ImageThunkData->u1.AddressOfData);
                FunctionAddress=(DWORD)MiFindExportedRoutine(ModuleBase,TRUE,ImortByName->Name,0);
                if (FunctionAddress==0)
                {
                    return FALSE;
                }
                FirstThunk->u1.Function=FunctionAddress;
            }
            FirstThunk++;
            ImageThunkData++;
        }
        ImageImportDescriptor++;
    }
    return TRUE;
}
```
### 5.修复重定位表

```cpp
/*
重定位表  修复
*/
BOOLEAN
    FixBaseRelocTable (
    PVOID NewImageBase,
    DWORD ExistImageBase
    )
{
    LONGLONG Diff;
    ULONG TotalCountBytes = 0;
    ULONG_PTR VA;
    ULONGLONG OriginalImageBase;
    ULONG SizeOfBlock;
    PUCHAR FixupVA;
    USHORT Offset;
    PUSHORT NextOffset = NULL;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION NextBlock;


    NtHeaders = RtlImageNtHeader( NewImageBase );
    if (NtHeaders == NULL) 
    {
        return FALSE;
    }

    switch (NtHeaders->OptionalHeader.Magic) {

    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        OriginalImageBase =
            ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.ImageBase;
        break;

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        OriginalImageBase =
            ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.ImageBase;
        break;

    default:
        return FALSE;
    }

    //
    // Locate the relocation section.
    //

    NextBlock = (PIMAGE_BASE_RELOCATION)RtlImageDirectoryEntryToData(
        NewImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &TotalCountBytes);

    //
    // It is possible for a file to have no relocations, but the relocations
    // must not have been stripped.
    //

    if (!NextBlock || !TotalCountBytes) 
    {

        if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) 
        {
            DbgPrint("Image can't be relocated, no fixup information.\n");
            return FALSE;

        }
        else 
        {
            return TRUE;
        }

    }

    //
    // If the image has a relocation table, then apply the specified fixup
    // information to the image.
    //
    Diff = (ULONG_PTR)ExistImageBase - OriginalImageBase;
    while (TotalCountBytes)
    {
        SizeOfBlock = NextBlock->SizeOfBlock;
        TotalCountBytes -= SizeOfBlock;
        SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
        SizeOfBlock /= sizeof(USHORT);
        NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));

        VA = (ULONG_PTR)NewImageBase + NextBlock->VirtualAddress;

        if ( !(NextBlock = LdrProcessRelocationBlockLongLong( VA,
            SizeOfBlock,
            NextOffset,
            Diff)) ) 
        {

            DbgPrint("%s: Unknown base relocation type\n");
            return FALSE;

        }
    }

    return TRUE;
}



/*修复重定位表*/
PIMAGE_BASE_RELOCATION
    LdrProcessRelocationBlockLongLong(
    IN ULONG_PTR VA,
    IN ULONG SizeOfBlock,
    IN PUSHORT NextOffset,
    IN LONGLONG Diff
    )
{
    PUCHAR FixupVA;
    USHORT Offset;
    LONG Temp;
    ULONG Temp32;
    ULONGLONG Value64;
    LONGLONG Temp64;



    while (SizeOfBlock--) {

        Offset = *NextOffset & (USHORT)0xfff;
        FixupVA = (PUCHAR)(VA + Offset);

        //
        // Apply the fixups.
        //

        switch ((*NextOffset) >> 12) {

        case IMAGE_REL_BASED_HIGHLOW :
            //
            // HighLow - (32-bits) relocate the high and low half
            //      of an address.
            //
            *(LONG UNALIGNED *)FixupVA += (ULONG) Diff;
            break;

        case IMAGE_REL_BASED_HIGH :
            //
            // High - (16-bits) relocate the high half of an address.
            //
            Temp = *(PUSHORT)FixupVA << 16;
            Temp += (ULONG) Diff;
            *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
            break;

        case IMAGE_REL_BASED_HIGHADJ :
            //
            // Adjust high - (16-bits) relocate the high half of an
            //      address and adjust for sign extension of low half.
            //

            //
            // If the address has already been relocated then don't
            // process it again now or information will be lost.
            //
            if (Offset & LDRP_RELOCATION_FINAL) {
                ++NextOffset;
                --SizeOfBlock;
                break;
            }

            Temp = *(PUSHORT)FixupVA << 16;
            ++NextOffset;
            --SizeOfBlock;
            Temp += (LONG)(*(PSHORT)NextOffset);
            Temp += (ULONG) Diff;
            Temp += 0x8000;
            *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);

            break;

        case IMAGE_REL_BASED_LOW :
            //
            // Low - (16-bit) relocate the low half of an address.
            //
            Temp = *(PSHORT)FixupVA;
            Temp += (ULONG) Diff;
            *(PUSHORT)FixupVA = (USHORT)Temp;
            break;

        case IMAGE_REL_BASED_IA64_IMM64:

            //
            // Align it to bundle address before fixing up the
            // 64-bit immediate value of the movl instruction.
            //

            FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
            Value64 = (ULONGLONG)0;

            //
            // Extract the lower 32 bits of IMM64 from bundle
            //


            EXT_IMM64(Value64,
                (PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
                EMARCH_ENC_I17_IMM7B_SIZE_X,
                EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM7B_VAL_POS_X);
            EXT_IMM64(Value64,
                (PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
                EMARCH_ENC_I17_IMM9D_SIZE_X,
                EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM9D_VAL_POS_X);
            EXT_IMM64(Value64,
                (PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
                EMARCH_ENC_I17_IMM5C_SIZE_X,
                EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM5C_VAL_POS_X);
            EXT_IMM64(Value64,
                (PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
                EMARCH_ENC_I17_IC_SIZE_X,
                EMARCH_ENC_I17_IC_INST_WORD_POS_X,
                EMARCH_ENC_I17_IC_VAL_POS_X);
            EXT_IMM64(Value64,
                (PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
                EMARCH_ENC_I17_IMM41a_SIZE_X,
                EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41a_VAL_POS_X);

            EXT_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
                EMARCH_ENC_I17_IMM41b_SIZE_X,
                EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41b_VAL_POS_X);
            EXT_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
                EMARCH_ENC_I17_IMM41c_SIZE_X,
                EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41c_VAL_POS_X);
            EXT_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
                EMARCH_ENC_I17_SIGN_SIZE_X,
                EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
                EMARCH_ENC_I17_SIGN_VAL_POS_X);
            //
            // Update 64-bit address
            //

            Value64+=Diff;

            //
            // Insert IMM64 into bundle
            //

            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
                EMARCH_ENC_I17_IMM7B_SIZE_X,
                EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM7B_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
                EMARCH_ENC_I17_IMM9D_SIZE_X,
                EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM9D_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
                EMARCH_ENC_I17_IMM5C_SIZE_X,
                EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM5C_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
                EMARCH_ENC_I17_IC_SIZE_X,
                EMARCH_ENC_I17_IC_INST_WORD_POS_X,
                EMARCH_ENC_I17_IC_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
                EMARCH_ENC_I17_IMM41a_SIZE_X,
                EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41a_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
                EMARCH_ENC_I17_IMM41b_SIZE_X,
                EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41b_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
                EMARCH_ENC_I17_IMM41c_SIZE_X,
                EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
                EMARCH_ENC_I17_IMM41c_VAL_POS_X);
            INS_IMM64(Value64,
                ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
                EMARCH_ENC_I17_SIGN_SIZE_X,
                EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
                EMARCH_ENC_I17_SIGN_VAL_POS_X);
            break;

        case IMAGE_REL_BASED_DIR64:

            *(ULONGLONG UNALIGNED *)FixupVA += Diff;

            break;

        case IMAGE_REL_BASED_MIPS_JMPADDR :
            //
            // JumpAddress - (32-bits) relocate a MIPS jump address.
            //
            Temp = (*(PULONG)FixupVA & 0x3ffffff) << 2;
            Temp += (ULONG) Diff;
            *(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
                ((Temp >> 2) & 0x3ffffff);

            break;

        case IMAGE_REL_BASED_ABSOLUTE :
            //
            // Absolute - no fixup required.
            //
            break;

        case IMAGE_REL_BASED_SECTION :
            //
            // Section Relative reloc.  Ignore for now.
            //
            break;

        case IMAGE_REL_BASED_REL32 :
            //
            // Relative intrasection. Ignore for now.
            //
            break;

        default :
            //
            // Illegal - illegal relocation type.
            //

            return (PIMAGE_BASE_RELOCATION)NULL;
        }
        ++NextOffset;
    }
    return (PIMAGE_BASE_RELOCATION)NextOffset;
}
```
### 6.获得ssdt在Reload中的偏移

```cpp
//通过KeServiceDescriptorTable的RVA与重定位表项解析的地址RVA比较，一致则取出其中的SSDT表地址
BOOLEAN GetOriginalKiServiceTable(BYTE *NewImageBase,DWORD ExistImageBase,DWORD *NewKiServiceTable)
{
    PIMAGE_DOS_HEADER ImageDosHeader;
    PIMAGE_NT_HEADERS ImageNtHeaders;
    DWORD KeServiceDescriptorTableRva;
    PIMAGE_BASE_RELOCATION ImageBaseReloc=NULL;
    DWORD RelocSize;
    int ItemCount,Index;
    int Type;
    PDWORD RelocAddress;
    DWORD RvaData;
    DWORD count=0;
    WORD *TypeOffset;


    ImageDosHeader=(PIMAGE_DOS_HEADER)NewImageBase;
    if (ImageDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }
    ImageNtHeaders=(PIMAGE_NT_HEADERS)(NewImageBase+ImageDosHeader->e_lfanew);
    if (ImageNtHeaders->Signature!=IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }
    KeServiceDescriptorTableRva=(DWORD)MiFindExportedRoutine(NewImageBase,TRUE,"KeServiceDescriptorTable",0);
    if (KeServiceDescriptorTableRva==0)
    {
        return FALSE;
    }

    KeServiceDescriptorTableRva=KeServiceDescriptorTableRva-(DWORD)NewImageBase;
    ImageBaseReloc=RtlImageDirectoryEntryToData(NewImageBase,TRUE,IMAGE_DIRECTORY_ENTRY_BASERELOC,&RelocSize);
    if (ImageBaseReloc==NULL)
    {
        return FALSE;
    }

    while (ImageBaseReloc->SizeOfBlock)
    {  
        count++;
        ItemCount=(ImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
        TypeOffset=(WORD*)((DWORD)ImageBaseReloc+sizeof(IMAGE_BASE_RELOCATION));
        for (Index=0;Index<ItemCount;Index++)
        {
            Type=TypeOffset[Index]>>12;  //高4位是类型   低12位位页内偏移 4k  
            if (Type==3)
            {
                //Base + Virtual 定位到页   + 低12位  = RelocAddress 需要修复的地址
                RelocAddress=(PDWORD)((DWORD)(TypeOffset[Index]&0x0fff)+ImageBaseReloc->VirtualAddress+(DWORD)NewImageBase);
                RvaData=*RelocAddress-ExistImageBase;
                
                if (RvaData==KeServiceDescriptorTableRva)  //重定位表中的rva 是 KeServiceDescriptorTable 表项的
                {
                    if(*(USHORT*)((DWORD)RelocAddress-2)==0x05c7)
                    {
                        /*
                    1: kd> dd 0x89651c12   RelocAddress - 2
                    89651c12       79c005c7 bd9c83f8 

                    1: kd> dd KeServiceDescriptorTable           
                    83f879c0       83e9bd9c 00000000 00000191 83e9c3e4
                    83f879d0       00000000 00000000 00000000 00000000
                
                    1: kd> dd 0x89651c14        RelocAddress
                    89651c14       83f879c0 83e9bd9c 79c41589 c8a383f8
                    89651c24       c783f879 f879cc05 e9c3e483 d8158983
                        */
                        //RelocAddress 里面存放着 KeServiceDesriptorTable地址  
                        //RelocAddress + 4 存放着 KeServiceDesriptorTable第一成员也就是SSDT基址
                        *NewKiServiceTable=*(DWORD*)((DWORD)RelocAddress+4)-ExistImageBase+(DWORD)NewImageBase;
                        return TRUE;
                    }
                }

            }

        }
        ImageBaseReloc=(PIMAGE_BASE_RELOCATION)((DWORD)ImageBaseReloc+ImageBaseReloc->SizeOfBlock);
    }

    return FALSE;
}
```
### 7.修复SSDT

```cpp
VOID FixOriginalKiServiceTable(PDWORD OriginalKiServiceTable,DWORD ModuleBase,DWORD ExistImageBase)
{
    DWORD FuctionCount;
    DWORD Index;
    FuctionCount=KeServiceDescriptorTable->TableSize; //函数个数
    
    KdPrint(("ssdt funcion count:%X---KiServiceTable:%X\n",FuctionCount,KeServiceDescriptorTable->ServiceTable));    
    for (Index=0;Index<FuctionCount;Index++)
    {
        OriginalKiServiceTable[Index]=OriginalKiServiceTable[Index]-ExistImageBase+ModuleBase; //修复SSDT函数地址
    }
}
```
### 8.提供获取函数地址的函数 
```cpp
/*
输入FuncName  、 原来Ntos地址  、自己重载 Ntos地址
//第一次都是通过  系统的原来偏移 + NewBase 获得函数地址  
//然后通过自己的RMmGetSystemRoutineAddress获得 偏移+NewBase 获得函数地址
还不能找到则遍历导出表
*/
ULONG ReLoadNtosCALL(WCHAR *lpwzFuncTion,ULONG ulOldNtosBase,ULONG ulReloadNtosBase)
{
    UNICODE_STRING UnicodeFunctionName;
    ULONG ulOldFunctionAddress;
    ULONG ulReloadFunctionAddress;
    int index=0;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS NtDllHeader;

    IMAGE_OPTIONAL_HEADER opthdr;
    DWORD* arrayOfFunctionAddresses;
    DWORD* arrayOfFunctionNames;
    WORD* arrayOfFunctionOrdinals;
    DWORD functionOrdinal;
    DWORD Base, x, functionAddress,position;
    char* functionName;
    IMAGE_EXPORT_DIRECTORY *pExportTable;
    ULONG ulNtDllModuleBase;

    UNICODE_STRING UnicodeFunction;
    UNICODE_STRING UnicodeExportTableFunction;
    ANSI_STRING ExportTableFunction;
    //第一次都是通过  系统的原来偏移 + NewBase 获得函数地址  
    //然后通过自己的RMmGetSystemRoutineAddress获得 偏移+NewBase 获得函数地址
    __try
    {
        if (RRtlInitUnicodeString &&
            RRtlCompareUnicodeString &&
            RMmGetSystemRoutineAddress &&
            RMmIsAddressValid)
        {
            RRtlInitUnicodeString(&UnicodeFunctionName,lpwzFuncTion);
            ulOldFunctionAddress = (DWORD)RMmGetSystemRoutineAddress(&UnicodeFunctionName);
            ulReloadFunctionAddress = ulOldFunctionAddress - ulOldNtosBase + ulReloadNtosBase; //获得重载的FuncAddr
            if (RMmIsAddressValid(ulReloadFunctionAddress)) //如果无效就从 导出表  获取？  应该不会无效
            {
                return ulReloadFunctionAddress;
            }
            //从导出表里获取
            ulNtDllModuleBase = ulReloadNtosBase;
            pDosHeader = (PIMAGE_DOS_HEADER)ulReloadNtosBase;
            if (pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
            {
                KdPrint(("failed to find NtHeader\r\n"));
                return NULL;
            }
            NtDllHeader=(PIMAGE_NT_HEADERS)(ULONG)((ULONG)pDosHeader+pDosHeader->e_lfanew);
            if (NtDllHeader->Signature!=IMAGE_NT_SIGNATURE)
            {
                KdPrint(("failed to find NtHeader\r\n"));
                return NULL;
            }
            opthdr = NtDllHeader->OptionalHeader;
            pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*)ulNtDllModuleBase + opthdr.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress); //得到导出表
            arrayOfFunctionAddresses = (DWORD*)( (BYTE*)ulNtDllModuleBase + pExportTable->AddressOfFunctions);  //地址表
            arrayOfFunctionNames = (DWORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNames);         //函数名表
            arrayOfFunctionOrdinals = (WORD*)((BYTE*)ulNtDllModuleBase + pExportTable->AddressOfNameOrdinals);

            Base = pExportTable->Base;

            for(x = 0; x < pExportTable->NumberOfFunctions; x++) //在整个导出表里扫描
            {
                functionName = (char*)( (BYTE*)ulNtDllModuleBase + arrayOfFunctionNames[x]);
                functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; 
                functionAddress = (DWORD)((BYTE*)ulNtDllModuleBase + arrayOfFunctionAddresses[functionOrdinal]);
                RtlInitAnsiString(&ExportTableFunction,functionName);
                RtlAnsiStringToUnicodeString(&UnicodeExportTableFunction,&ExportTableFunction,TRUE);

                RRtlInitUnicodeString(&UnicodeFunction,lpwzFuncTion);
                if (RRtlCompareUnicodeString(&UnicodeExportTableFunction,&UnicodeFunction,TRUE) == 0)
                {
                    RtlFreeUnicodeString(&UnicodeExportTableFunction);
                    return functionAddress;
                }
                RtlFreeUnicodeString(&UnicodeExportTableFunction);
            }
            return NULL;
        }
        RtlInitUnicodeString(&UnicodeFunctionName,lpwzFuncTion);
        ulOldFunctionAddress = (DWORD)MmGetSystemRoutineAddress(&UnicodeFunctionName);
        ulReloadFunctionAddress = ulOldFunctionAddress - ulOldNtosBase + ulReloadNtosBase;

        //KdPrint(("%ws:%08x:%08x",lpwzFuncTion,ulOldFunctionAddress,ulReloadFunctionAddress));

        if (MmIsAddressValid(ulReloadFunctionAddress))
        {
            return ulReloadFunctionAddress;
        }
        //         

    }__except(EXCEPTION_EXECUTE_HANDLER){
        KdPrint(("EXCEPTION_EXECUTE_HANDLER"));
    }
    return NULL;
}
```
## 四、代码下载
[https://github.com/LycorisGuard/Windows-Rootkits/tree/master/ReloadKernel-XP](https://github.com/LycorisGuard/Windows-Rootkits/tree/master/ReloadKernel-XP)