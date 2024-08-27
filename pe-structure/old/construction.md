[TOC]

# DOS Header
|DOS header|
|-|
|DOS 'MZ' header|
|DOS stub|
|'PE',0,0|
|IMAGE_FILE_HEADER|
|IMAGE_OPTIONAL_HEADER32|
|data directory table|
|IMAGE_SECTION_HEADER|
|...|
|IMAGE_SECTION_HEADER|
|.text|
|.data|
|.edata|
|.reloc|
|...|
|COFF line number|
|COFF symbol table|
|code view debug infomation|

![](U:\doc\system\windows\PE\graph\OIP-C.jpg)
```c++
  typedef struct _IMAGE_DOS_HEADER 
 {                                          // DOS .EXE header
  +0   WORD   e_magic;                     // Magic number
  +2   WORD   e_cblp;                      // Bytes on last page of file
  +4   WORD   e_cp;                        // Pages in file
  +6   WORD   e_crlc;                      // Relocations
  +8   WORD   e_cparhdr;                   // Size of header in paragraphs
  +A   WORD   e_minalloc;                  // Minimum extra paragraphs needed
  +C   WORD   e_maxalloc;                  // Maximum extra paragraphs needed
  +E   WORD   e_ss;                        // Initial (relative) SS value
 +10   WORD   e_sp;                        // Initial SP value
 +12   WORD   e_csum;                      // Checksum
 +14    WORD   e_ip;                        // Initial IP value
 +16    WORD   e_cs;                        // Initial (relative) CS value
 +18    WORD   e_lfarlc;                    // File address of relocation table
 +1A    WORD   e_ovno;                      // Overlay number
 +1C    WORD   e_res[4];                    // Reserved words
 +24    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
 +26    WORD   e_oeminfo;                   // OEM information; e_oemid specific
 +28    WORD   e_res2[10];                  // Reserved words
 +3C    LONG   e_lfanew;                    // File address of new exe header
   
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```
e_magic='MZ'
the most important : e_lfanew : the offset of PE header


```c++
 typedef struct _IMAGE_NT_HEADERS
 {
 +00h    DWORD Signature;
 +04h    IMAGE_FILE_HEADER FileHeader;
  ???    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
 } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```



```c++
struct _IMAGE_FILE_HEADER{
    0x00 WORD Machine;                  //※程序执行的CPU平台:0X0:任何平台，0X14C:intel i386及后续处理器
    0x02 WORD NumberOfSections;         //※PE文件中区块数量
    0x04 DWORD TimeDateStamp;           //时间戳：连接器产生此文件的时间距1969/12/31-16:00P:00的总秒数
    0x08 DWORD PointerToSymbolTable;  //COFF符号表格的偏移位置。此字段只对COFF除错信息有用
    0x0c DWORD NumberOfSymbols;       //COFF符号表格中的符号个数。该值和上一个值在release版本的程序里为0
    0x10 WORD SizeOfOptionalHeader;   //IMAGE_OPTIONAL_HEADER结构的大小(字节数):32位默认E0H,64位默认F0H(可修改)
    0x12 WORD Characteristics;          //※描述文件属性,eg:
                                        //单属性(只有1bit为1)：#define IMAGE_FILE_DLL 0x2000  //File is a DLL.
                                        //组合属性(多个bit为1，单属性或运算):0X010F 可执行文件
}
```

```c++
struct _IMAGE_OPTIONAL_HEADER{
    0x00 WORD Magic;                    //※幻数(魔数)，0x0107:ROM image,0x010B:32位PE，0X020B:64位PE 
    //0x02 BYTE MajorLinkerVersion;     //连接器主版本号
    //0x03 BYTE MinorLinkerVersion;     //连接器副版本号
    0x04 DWORD SizeOfCode;              //所有代码段的总和大小,注意：必须是FileAlignment的整数倍,存在但没用
    0x08 DWORD SizeOfInitializedData;   //已经初始化数据的大小,注意：必须是FileAlignment的整数倍,存在但没用
    0x0c DWORD SizeOfUninitializedData; //未经初始化数据的大小,注意：必须是FileAlignment的整数倍,存在但没用
    0x10 DWORD AddressOfEntryPoint;     //※程序入口地址OEP，这是一个RVA(Relative Virtual Address),通常会落在.textsection,此字段对于DLLs/EXEs都适用。
    0x14 DWORD BaseOfCode;              //代码段起始地址(代码基址),(代码的开始和程序无必然联系)
    0x18 DWORD BaseOfData;              //数据段起始地址(数据基址)
    0x1c DWORD ImageBase;               //※内存镜像基址(默认装入起始地址),默认为4000H
    0x20 DWORD SectionAlignment;        //※内存对齐:一旦映像到内存中，每一个section保证从一个「此值之倍数」的虚拟地址开始
    0x24 DWORD FileAlignment;           //※文件对齐：最初是200H，现在是1000H
    //0x28 WORD MajorOperatingSystemVersion;    //所需操作系统主版本号
    //0x2a WORD MinorOperatingSystemVersion;    //所需操作系统副版本号
    //0x2c WORD MajorImageVersion;              //自定义主版本号,使用连接器的参数设置,eg:LINK /VERSION:2.0 myobj.obj
    //0x2e WORD MinorImageVersion;              //自定义副版本号,使用连接器的参数设置
    //0x30 WORD MajorSubsystemVersion;          //所需子系统主版本号,典型数值4.0(Windows 4.0/即Windows 95)
    //0x32 WORD MinorSubsystemVersion;          //所需子系统副版本号
    //0x34 DWORD Win32VersionValue;             //总是0
    0x38 DWORD SizeOfImage;         //※PE文件在内存中映像总大小,sizeof(ImageBuffer),SectionAlignment的倍数
    0x3c DWORD SizeOfHeaders;       //※DOS头(64B)+PE标记(4B)+标准PE头(20B)+可选PE头+节表的总大小，按照文件对齐(FileAlignment的倍数)
    0x40 DWORD CheckSum;            //PE文件CRC校验和，判断文件是否被修改
    //0x44 WORD Subsystem;          //用户界面使用的子系统类型
    //0x46 WORD DllCharacteristics;   //总是0
    0x48 DWORD SizeOfStackReserve;  //默认线程初始化栈的保留大小
    0x4c DWORD SizeOfStackCommit;   //初始化时实际提交的线程栈大小
    0x50 DWORD SizeOfHeapReserve;   //默认保留给初始化的process heap的虚拟内存大小
    0x54 DWORD SizeOfHeapCommit;    //初始化时实际提交的process heap大小
    //0x58 DWORD LoaderFlags;       //总是0
    0x5c DWORD NumberOfRvaAndSizes; //目录项数目：总为0X00000010H(16)
    0x60 _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
}
```

```c++
typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;    // 数据表的起始虚拟地址
    DWORD Size;    // 数据表大小
}IMAGE_DATA_DIRECTORY,*IMAGE_DATA_DIRECTORY

```
16个数据表依次如下：
        导出表、导入表、资源表、异常处理表、安全表、重定位表、调试表、版权、指针目录、TLS、载入配置、绑定输入目录、导入地址表、延迟载入、COM信息。


```c++
typedef struct _IMAGE_SECTION_HEADER 

{
+0h BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; // 节表名称,如“.text” 
//IMAGE_SIZEOF_SHORT_NAME=8
union
+8h {
DWORD PhysicalAddress; // 物理地址
DWORD VirtualSize; // 真实长度，这两个值是一个联合结构，可以使用其中的任何一个，一 般是取后一个
} Misc;
+ch DWORD VirtualAddress; // 节区的 RVA 地址
+10h DWO RD SizeOfRawData; // 在文件中对齐后的尺寸
+14h DWORD PointerToRawData; // 在文件中的偏移量
+18h DWORD PointerToRelocations; // 在OBJ文件中使用，重定位的偏移
+1ch DWORD PointerToLinenumbers; // 行号表的偏移（供调试使用地）
+1eh WORD NumberOfRelocations; // 在OBJ文件中使用，重定位项数目
+20h WORD NumberOfLinenumbers; // 行号表中行号的数目
+24h DWORD Characteristics; // 节属性如可读，可写，可执行等} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

```

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR 
{
    union 
    {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // 包含指IMAGE_DATA（输入名称表）RVA 的结构数组
    };
    DWORD    TimeDateStamp;
    DWORD     ForwarderChain;
    DWORD     Name;
    DWORD      FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

```
OriginalFirstThunk
它指向first thunk，IMAGE_THUNK_DATA，该thunk拥有Hint和Function name的地址。

TimeDateStamp
如果那里有绑定的话它包含时间/数据戳（time/data stamp）。如果它是0，就没有绑定在被导入的DLL中发生。在最近，它被设置为0xFFFFFFFF以表示绑定发生。

ForwarderChain
在老版的绑定中，它引用API的第一个forwarder chain（传递器链表）。它可被设置为0xFFFFFFFF以代表没有forwarder。

Name
它表示DLL 名称的相对虚地址（译注：相对一个用null作为结束符的ASCII字符串的一个RVA，该字符串是该导入DLL文件的名称，如：KERNEL32.DLL）。

FirstThunk
它包含由IMAGE_THUNK_DATA定义的 first thunk数组的虚地址，通过loader用函数虚地址初始化thunk。在Orignal First Thunk缺席下，它指向first thunk：Hints和The Function names的thunks。



```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;    // 不加红的不重要
    DWORD   TimeDateStamp;      //时间戳.  编译的时间. 把秒转为时间.可以知道这个DLL是什么时候编译出来的.
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;　　　　　　　　　　　//指向该导出表文件名的字符串,也就是这个DLL的名称  辅助信息.修改不影响  存储的RVA 如果想在文件中查看.自己计算一下FOA即可.
    DWORD   Base; 　　　　　　　　　　// 导出函数的起始序号
    DWORD   NumberOfFunctions;     //所有的导出函数的个数
    DWORD   NumberOfNames;         //以名字导出的函数的个数
    DWORD   AddressOfFunctions;     // 导出的函数地址的 地址表  RVA  也就是 函数地址表  
    DWORD   AddressOfNames;         // 导出的函数名称表的  RVA      也就是 函数名称表
    DWORD   AddressOfNameOrdinals;  // 导出函数序号表的RVA         也就是 函数序号表
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```



