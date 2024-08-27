#include<stdio.h>
#include<windows.h>

int main()
{
    char filepath[]="U:\\doc\\system\\windows\\hello.exe";

    HANDLE hFile=CreateFileA(filepath,GENERIC_ALL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hFile==INVALID_HANDLE_VALUE)
    {
        printf("open file fail\n");
        exit(0);
    }
    

    HANDLE hMapping=CreateFileMappingA(hFile,NULL,PAGE_READWRITE,0,0,NULL);
    if(!hMapping)
    {
        CloseHandle(hFile);
        printf("mapping fail\n");
        exit(0);
    }

    LPVOID ImageBase=MapViewOfFile(hMapping,FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_ALL_ACCESS,0,0,0);
    if(!ImageBase)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        printf("map view fail\n");
        exit(0);
    }

    PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)ImageBase;
    if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    {
        printf("not PE\n");
        return 0;
    }

    PIMAGE_NT_HEADERS32 pNTHeader=(PIMAGE_NT_HEADERS32)((long long)pDosHeader+(long long)pDosHeader->e_lfanew);
    if(pNTHeader->Signature!=IMAGE_NT_SIGNATURE)
    {
        printf("not PE\n");
        return 0;
    }


    PIMAGE_FILE_HEADER pFileHeader=&pNTHeader->FileHeader;
    if(pFileHeader->NumberOfSections==1)
    {
        printf("file may be packed\n");
        return 0;
    }

    PIMAGE_OPTIONAL_HEADER32 POptHeader=(PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;

    

    PIMAGE_SECTION_HEADER pSecHeader=IMAGE_FIRST_SECTION(pNTHeader);

    

    PIMAGE_DATA_DIRECTORY pDataDi=(PIMAGE_DATA_DIRECTORY)&pNTHeader->OptionalHeader.DataDirectory[0];


    PIMAGE_DATA_DIRECTORY pImportDi=(PIMAGE_DATA_DIRECTORY)&pNTHeader->OptionalHeader.DataDirectory[1];



    PIMAGE_IMPORT_DESCRIPTOR pImportDe=(PIMAGE_IMPORT_DESCRIPTOR)(pImportDi->VirtualAddress+(DWORD64)ImageBase);

    printf("%X\n",*pImportDe);



 

    UnmapViewOfFile(ImageBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);


    printf("OK\n");
}