#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<cstring>
#include<iostream>

using namespace std;

typedef struct DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovnp;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
};

typedef struct FILE_HEADER
{
    WORD machine;
    WORD numberofsection;
    DWORD timedatastamp;
    DWORD pointertostmboltabale;
    DWORD numberofsymbols;
    WORD sizeofoptionalheader;
    WORD characteristics;
};

typedef struct DATA_DIRECTORY
{
    DWORD virtualaddress;
    DWORD size;
};

typedef struct OPTIONAL_HEADER32
{
    WORD magic;
    BYTE majorlinkerversion;
    BYTE minorlinkerversion;
    DWORD sizeofcode;
    DWORD sizeofinitializeddata;
    DWORD sizeofuninitializeddata;
    DWORD addressofentrypoint;
    DWORD baseofcode;
    DWORD baseofdata;
    DWORD imagebase;
    DWORD sectionalignment;
    DWORD filealignment;
    WORD majoroperatingsystemversion;
    WORD minoroperatingsystemversion;
    WORD majorimageversion;
    WORD minorimageversion;
    WORD majorsubsystemversion;
    WORD minorsubsystemversion;
    DWORD sizeofimage;
    DWORD sizeofheaders;
    DWORD checksum;
    WORD subsystem;
    WORD dllcharacteristics;
    DWORD sizeofstackreverse;
    DWORD sizeofstackcommit;
    DWORD sizeofheapreverse;
    DWORD sizeofheapcommit;
    DWORD loaderflags;
    DWORD numberofrvaandsizes;
    DATA_DIRECTORY datadirectory[16];
};

typedef struct NT_HEADER
{
    DWORD signature;
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER32 optional_header;
};


typedef struct SECTION_HEADER
{
    BYTE Name[8];
    union
    {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    };
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD NumberOfRelocations;
    WORD NumberOFLineNumbers;
    DWORD Characteristics;

};

typedef struct IMPORT_DESCRIPTOR
{
    union
    {
        DWORD characteristics;
        DWORD orignalfirstthunk;
    };
    DWORD timedatastamp;
    DWORD forwarderchain;
    DWORD name;
    DWORD firstthunk;
};

typedef struct EXPORT_DIRECTORY
{
    DWORD characteristics;
    DWORD timedatestamp;
    WORD majorversion;
    WORD minorversion;
    DWORD name;
    DWORD base;
    DWORD numberoffunctions;
    DWORD numberofnames;
    DWORD addressoffunctions;
    DWORD addressofnames;
    DWORD addressofnameordinals;
};

typedef struct IMPORT_DESCRIPTOR
{
    union
    {
        DWORD Characteristics;
        DWORD  OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
};

typedef struct EXPORT_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
};

void GetDosHeader(FILE *fp,DOS_HEADER *dos_header)
{
    int i=0;
    fread(&dos_header->e_magic,2,1,fp);
    fread(&dos_header->e_cblp,2,1,fp);
    fread(&dos_header->e_cp,2,1,fp);
    fread(&dos_header->e_crlc,2,1,fp);
    fread(&dos_header->e_cparhdr,2,1,fp);
    fread(&dos_header->e_minalloc,2,1,fp);
    fread(&dos_header->e_maxalloc,2,1,fp);
    fread(&dos_header->e_ss,2,1,fp);
    fread(&dos_header->e_sp,2,1,fp);
    fread(&dos_header->e_csum,2,1,fp);
    fread(&dos_header->e_ip,2,1,fp);
    fread(&dos_header->e_cs,2,1,fp);
    fread(&dos_header->e_lfarlc,2,1,fp);
    fread(&dos_header->e_ovnp,2,1,fp);
    while(i<4)
    {
        fread(&dos_header->e_res[i],2,1,fp);
        i++;
    }
    fread(&dos_header->e_oemid,2,1,fp);
    fread(&dos_header->e_oeminfo,2,1,fp);
    i=0;
    while(i<10)
    {
        fread(&dos_header->e_res2[i],2,1,fp);
        i++;
    }
    fread(&dos_header->e_lfanew,2,1,fp);


}

void PrintDosHeader(FILE *fp,DOS_HEADER *dos_header)
{
    int i=0;
    printf("----------DOS HEADER----------\n");
    printf("e_magic:%X\t%d\n",dos_header->e_magic,dos_header->e_magic);
    printf("e_cblp:%X\t%d\n",dos_header->e_cblp,dos_header->e_cblp);
    printf("e_cp:%X\t%d\n",dos_header->e_cp,dos_header->e_cp);
    printf("e_crlc:%X\t%d\n",dos_header->e_crlc,dos_header->e_crlc);
    printf("e_cparhdr:%X\t%d\n",dos_header->e_cparhdr,dos_header->e_cparhdr);
    printf("e_minalloc:%X\t%d\n",dos_header->e_minalloc,dos_header->e_minalloc);
    printf("e_maxalloc:%X\t%d\n",dos_header->e_maxalloc,dos_header->e_maxalloc);
    printf("e_ss:%X\t%d\n",dos_header->e_ss,dos_header->e_ss);
    printf("e_sp:%X\t%d\n",dos_header->e_sp,dos_header->e_sp);
    printf("e_csum:%X\t%d\n",dos_header->e_csum,dos_header->e_csum);
    printf("e_ip:%X\t%d\n",dos_header->e_ip,dos_header->e_ip);
    printf("e_cs:%X\t%d\n",dos_header->e_cs,dos_header->e_cs);
    printf("e_lfarlc:%X\t%d\n",dos_header->e_lfarlc,dos_header->e_lfarlc);
    printf("e_ovnp:%X\t%d\n",dos_header->e_ovnp,dos_header->e_ovnp);
    while(i<4)
    {
        printf("e_res[%d]:%X\t%d\n",i,dos_header->e_res[i],dos_header->e_res[i]);
        i++;
    }
    printf("e_oemid:%X\t%d\n",dos_header->e_oemid,dos_header->e_oemid);
    printf("e_oemindo:%X\t%d\n",dos_header->e_oeminfo,dos_header->e_oeminfo);
    i=0;
    while(i<10)
    {
        printf("e_res2[%d]:%X\t%d\n",i,dos_header->e_res2[i],dos_header->e_res2[i]);
        i++;
    }
    printf("e_lfanew:%X\t%d\n",dos_header->e_lfanew,dos_header->e_lfanew);
    
    printf("----------size:%X\t%d----------\n",sizeof(DOS_HEADER),sizeof(DOS_HEADER));
}
/*string dos_header_mem[]={"e_magic","e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp","e_csum","e_ip","e_cs",
"e_lfarlc","e_ovnp","e_res","e_oemid","e_oeminfo","e_res2","e_lfanew"};*/

void GetNTHeader(FILE *fp,NT_HEADER *nt_header)
{
    int i=0;

    fread(&nt_header->signature,4,1,fp);
    
    fread(&nt_header->file_header.Machine,2,1,fp);
    fread(&nt_header->file_header.NumberOfSections,2,1,fp);
    fread(&nt_header->file_header.TimeDateStamp,4,1,fp);
    fread(&nt_header->file_header.PointerToSymbolTable,4,1,fp);
    fread(&nt_header->file_header.NumberOfSymbols,4,1,fp);
    fread(&nt_header->file_header.SizeOfOptionalHeader,2,1,fp);
    fread(&nt_header->file_header.Characteristics,2,1,fp);


    
    fread(&nt_header->optional_header.Magic,2,1,fp);
    fread(&nt_header->optional_header.MajorLinkerVersion,1,1,fp);
    fread(&nt_header->optional_header.MinorLinkerVersion,1,1,fp);
    fread(&nt_header->optional_header.SizeOfCode,4,1,fp);
    fread(&nt_header->optional_header.SizeOfInitializedData,4,1,fp);
    fread(&nt_header->optional_header.SizeOfUninitializedData,4,1,fp);
    fread(&nt_header->optional_header.AddressOfEntryPoint,4,1,fp);
    fread(&nt_header->optional_header.BaseOfCode,4,1,fp);
    fread(&nt_header->optional_header.BaseOfData,4,1,fp);
    fread(&nt_header->optional_header.ImageBase,4,1,fp);
    fread(&nt_header->optional_header.SectionAlignment,4,1,fp);
    fread(&nt_header->optional_header.FileAlignment,4,1,fp);
    fread(&nt_header->optional_header.MajorOperatingSystemVersion,2,1,fp);
    fread(&nt_header->optional_header.MinorOperatingSystemVersion,2,1,fp);
    fread(&nt_header->optional_header.MajorImageVersion,2,1,fp);
    fread(&nt_header->optional_header.MinorImageVersion,2,1,fp);
    fread(&nt_header->optional_header.MajorSubsystemVersion,2,1,fp);
    fread(&nt_header->optional_header.MinorSubsystemVersion,2,1,fp);
    fread(&nt_header->optional_header.Win32VersionValue,4,1,fp);
    fread(&nt_header->optional_header.SizeOfImage,4,1,fp);
    fread(&nt_header->optional_header.SizeOfHeaders,4,1,fp);
    fread(&nt_header->optional_header.CheckSum,4,1,fp);
    fread(&nt_header->optional_header.Subsystem,2,1,fp);
    fread(&nt_header->optional_header.DllCharacteristics,2,1,fp);
    fread(&nt_header->optional_header.SizeOfStackReserve,4,1,fp);
    fread(&nt_header->optional_header.SizeOfStackCommit,4,1,fp);
    fread(&nt_header->optional_header.SizeOfHeapReserve,4,1,fp);
    fread(&nt_header->optional_header.SizeOfHeapCommit,4,1,fp);
    fread(&nt_header->optional_header.LoaderFlags,4,1,fp);
    fread(&nt_header->optional_header.NumberOfRvaAndSizes,4,1,fp);

    while(i<16)
    {
        fread(&nt_header->optional_header.DataDirectory[i].VirtualAddress,4,1,fp);
        fread(&nt_header->optional_header.DataDirectory[i].Size,4,1,fp);
        i++;
    }

}

void PrintNTHeader(NT_HEADER *nt_header)
{
    int i=0;

    printf("----------NT Header----------\n");
    printf("signature:%X\t%d\n",nt_header->signature,nt_header->signature);

    printf("----------File Header----------\n");
    printf("Machine:%X\t%d\n",nt_header->file_header.Machine);
    printf("NumberOfSection:%X\t%d\n",nt_header->file_header.NumberOfSections,nt_header->file_header.NumberOfSections);
    printf("TimeDateStamp:%X\t%d\n",nt_header->file_header.TimeDateStamp,nt_header->file_header.TimeDateStamp);
    printf("PointertoSymbolTable:%X\t%d\n",nt_header->file_header.PointerToSymbolTable,nt_header->file_header.PointerToSymbolTable);
    printf("NumberOfSymbol:%X\t%d\n",nt_header->file_header.NumberOfSymbols,nt_header->file_header.NumberOfSymbols);
    printf("SizeOfOptionalheader:%X\t%d\n",nt_header->file_header.SizeOfOptionalHeader,nt_header->file_header.SizeOfOptionalHeader);
    printf("Characteristics:%X\t%d\n",nt_header->file_header.Characteristics,nt_header->file_header.Characteristics);
    printf("----------File Header Size:%X\t%d----------\n",sizeof(nt_header->file_header),sizeof(nt_header->file_header));

    printf("----------Optional Header----------\n");
    printf("Magic:%X\t%d\n",nt_header->optional_header.Magic,nt_header->optional_header.Magic);
    printf("MajorLinkerVersion:%X\t%d\n",nt_header->optional_header.MajorLinkerVersion,nt_header->optional_header.MajorLinkerVersion);
    printf("MinorLinkerVersion:%X\t%d\n",nt_header->optional_header.MinorLinkerVersion,nt_header->optional_header.MinorLinkerVersion);
    printf("SizeOfCode:%X\t%d\n",nt_header->optional_header.SizeOfCode,nt_header->optional_header.SizeOfCode);
    printf("SizeOfInitializedData:%X\t%d\n",nt_header->optional_header.SizeOfInitializedData,nt_header->optional_header.SizeOfInitializedData);
    printf("SizeOfUninitializedData:%X\t%d\n",nt_header->optional_header.SizeOfUninitializedData,nt_header->optional_header.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:%X\t%d\n",nt_header->optional_header.AddressOfEntryPoint,nt_header->optional_header.AddressOfEntryPoint);
    printf("BaseOfCode:%X\t%d\n",nt_header->optional_header.BaseOfCode,nt_header->optional_header.BaseOfCode);
    printf("BaseOfData:%X\t%d\n",nt_header->optional_header.BaseOfData,nt_header->optional_header.BaseOfData);
    printf("ImageBase:%X\t%d\n",nt_header->optional_header.ImageBase,nt_header->optional_header.ImageBase);
    printf("SectionAlignment:%X\t%d\n",nt_header->optional_header.SectionAlignment,nt_header->optional_header.SectionAlignment);
    printf("FileAlignment:%X\t%d\n",nt_header->optional_header.FileAlignment,nt_header->optional_header.FileAlignment);
    printf("MajorOperatingSystemVersion:%X\t%d\n",nt_header->optional_header.MajorOperatingSystemVersion,nt_header->optional_header.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion:%X\t%d\n",nt_header->optional_header.MinorOperatingSystemVersion,nt_header->optional_header.MinorOperatingSystemVersion);
    printf("MajorImageVersion:%X\t%d\n",nt_header->optional_header.MajorImageVersion,nt_header->optional_header.MajorImageVersion);
    printf("MinorImageVersion:%X\t%d\n",nt_header->optional_header.MinorImageVersion,nt_header->optional_header.MinorImageVersion);
    printf("MajorSubsystemVersion:%X\t%d\n",nt_header->optional_header.MajorSubsystemVersion,nt_header->optional_header.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:%X\t%d\n",nt_header->optional_header.MinorSubsystemVersion,nt_header->optional_header.MinorSubsystemVersion);
    printf("Win32VersionValue:%X\t%d\n",nt_header->optional_header.Win32VersionValue,nt_header->optional_header.Win32VersionValue);
    printf("SizeOfImage:%X\t%d\n",nt_header->optional_header.SizeOfImage,nt_header->optional_header.SizeOfImage);
    printf("SizeOfHeaders:%X\t%d\n",nt_header->optional_header.SizeOfHeaders,nt_header->optional_header.SizeOfHeaders);
    printf("CheckSum:%X\t%d\n",nt_header->optional_header.CheckSum,nt_header->optional_header.CheckSum);
    printf("Subsystem:%X\t%d\n",nt_header->optional_header.Subsystem,nt_header->optional_header.Subsystem);
    printf("DllCharacteristics:%X\t%d\n",nt_header->optional_header.DllCharacteristics,nt_header->optional_header.DllCharacteristics);
    printf("SizeOfStackReserve:%X\t%d\n",nt_header->optional_header.SizeOfStackReserve,nt_header->optional_header.SizeOfStackReserve);
    printf("SizeOfStackCommit:%X\t%d\n",nt_header->optional_header.SizeOfStackCommit,nt_header->optional_header.SizeOfStackCommit);
    printf("SizeOfHeapReserve:%X\t%d\n",nt_header->optional_header.SizeOfHeapReserve,nt_header->optional_header.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:%X\t%d\n",nt_header->optional_header.SizeOfHeapCommit,nt_header->optional_header.SizeOfHeapCommit);
    printf("LoaderFlags:%X\t%d\n",nt_header->optional_header.LoaderFlags,nt_header->optional_header.LoaderFlags);
    printf("NumberOfRvaAndSizes:%X\t%d\n",nt_header->optional_header.NumberOfRvaAndSizes,nt_header->optional_header.NumberOfRvaAndSizes);

    while(i<16)
    {
        printf("DataDirectory[%d]:VirtualAddress:%X\t%d\t---\tSize:%X\t%d\n",i,nt_header->optional_header.DataDirectory[i].VirtualAddress,nt_header->optional_header.DataDirectory[i].VirtualAddress,nt_header->optional_header.DataDirectory[i].Size,nt_header->optional_header.DataDirectory[i].Size);
        i++;
    }
    printf("----------Optional Header Size:%X\t%d----------\n",nt_header->file_header.SizeOfOptionalHeader,nt_header->file_header.SizeOfOptionalHeader);
}

void GetSectionHeader(FILE *fp,SECTION_HEADER **section_header,int n)
{
    int i=0;
    while(i<n)
    {
        fread(section_header[i]->Name,1,8,fp);
        fread(&section_header[i]->VirtualSize,4,1,fp);
        fread(&section_header[i]->VirtualAddress,4,1,fp);
        fread(&section_header[i]->SizeOfRawData,4,1,fp);
        fread(&section_header[i]->PointerToRawData,4,1,fp);
        fread(&section_header[i]->PointerToRelocations,4,1,fp);
        fread(&section_header[i]->PointerToLineNumbers,4,1,fp);
        fread(&section_header[i]->NumberOfRelocations,2,1,fp);
        fread(&section_header[i]->NumberOFLineNumbers,2,1,fp);
        fread(&section_header[i]->Characteristics,4,1,fp);
        i++;
    }
    
}

void PrintSectionHeader(SECTION_HEADER **section_header,int n)
{
    int i=0;

    printf("----------Section Header----------\n");
    while(i<n)
    {
        printf("\nName:%s\n",section_header[i]->Name);
        printf("VirtualSize:%X\t%d\n",section_header[i]->VirtualSize,section_header[i]->VirtualSize);
        printf("VirtualAddress:%X\t%d\n",section_header[i]->VirtualAddress,section_header[i]->VirtualAddress);
        printf("SizeOfRawData:%X\t%d\n",section_header[i]->SizeOfRawData,section_header[i]->SizeOfRawData);
        printf("PointerToRawData:%X\t%d\n",section_header[i]->PointerToRawData,section_header[i]->PointerToRawData);
        printf("PointerToRelocations:%X\t%d\n",section_header[i]->PointerToRelocations,section_header[i]->PointerToRelocations);
        printf("PointerToLineNumbers:%X\t%d\n",section_header[i]->PointerToLineNumbers,section_header[i]->PointerToLineNumbers);
        printf("NumberOfRelocations:%X\t%d\n",section_header[i]->NumberOfRelocations,section_header[i]->NumberOfRelocations);
        printf("NumberOFLineNumbers:%X\t%d\n",section_header[i]->NumberOFLineNumbers,section_header[i]->NumberOFLineNumbers);
        printf("Characteristics:%X\t%d\n",section_header[i]->Characteristics,section_header[i]->Characteristics);
        i++;
    }
    printf("----------Section Header Size:%X\t%d\n",n*sizeof(SECTION_HEADER),n*sizeof(SECTION_HEADER));
}




void PE_viewer(char *file)
{
    int i;
    char buf[100];
    FILE *fp;
    DOS_HEADER *dos_header;
    NT_HEADER *nt_header;
    SECTION_HEADER **section_header;
    dos_header=(DOS_HEADER*)malloc(sizeof(DOS_HEADER));
    nt_header=(NT_HEADER*)malloc(sizeof(NT_HEADER));
    section_header=(SECTION_HEADER**)malloc(sizeof(SECTION_HEADER*));
    fp=fopen(file,"rb");

    GetDosHeader(fp,dos_header);
    PrintDosHeader(fp,dos_header);

    printf("----------DOS stub----------\n");
    printf("----------size:%X\t%d----------\n",dos_header->e_lfanew-sizeof(DOS_HEADER),dos_header->e_lfanew-sizeof(DOS_HEADER));
    fseek(fp,dos_header->e_lfanew,SEEK_SET);

    GetNTHeader(fp,nt_header);
    PrintNTHeader(nt_header);
    
    i=0;
    while(i<nt_header->file_header.NumberOfSections)
    {
        section_header[i]=(SECTION_HEADER*)malloc(sizeof(SECTION_HEADER));
        i++;
    }
    GetSectionHeader(fp,section_header,nt_header->file_header.NumberOfSections);
    PrintSectionHeader(section_header,nt_header->file_header.NumberOfSections);

    fclose(fp);
}

int main()
{
    //char *file="U:\\doc\\system\\windows\\PE\\Project1.exe";
    char file[100]={0};
    scanf("%s",file);
    PE_viewer(file);
}