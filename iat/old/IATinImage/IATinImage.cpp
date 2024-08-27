#include<stdio.h>
#include<windows.h>

int main()
{
    char FilePath[]="U:\\doc\\system\\windows\\hello.exe";

    HANDLE hFile=CreateFileA(FilePath,GENERIC_ALL,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);

    LPVOID ImageBase=MapViewOfFile(hMapping,FILE_MAP_ALL_ACCESS,0,0,0);

    printf("%X\n",*(char*)((long long)ImageBase+0x1000));

    FILE *fp=fopen("image","wb");

    int i=0;
    while(i<0x3000)
    {
        fprintf(fp,"%c",*(char *)((long long )ImageBase+i));
        i++;
    }
}