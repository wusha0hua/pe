#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
using namespace std;

typedef struct
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
}SECTION;


bool section_adder(char *filepath)
{
    FILE *fp,*outfp;
    fp=fopen(filepath,"rb");
    outfp=fopen("output.exe","wb");

    int e_lfanew;
    WORD section_number;
    fseek(fp,0x3C,0);
    fread(&e_lfanew,4,1,fp);

    int sizeofheader=e_lfanew+0x4+0x12+0x2+0x60+0x80;

    rewind(fp);


    char *buf;
    buf=(char *)malloc(sizeofheader);

    fread(buf,1,sizeofheader,fp);

    fwrite(buf,1,sizeofheader,outfp);

    fseek(fp,e_lfanew+6,0);
    fread(&section_number,2,1,fp);

    fseek(outfp,e_lfanew+6,0);
    section_number++;
    fwrite(&section_number,2,1,outfp);

    fseek(fp,sizeofheader,0);
    fseek(outfp,sizeofheader,0);
    realloc(buf,6*0x28);
    fread(buf,1,5*0x28,fp);
    fwrite(buf,1,5*0x28,outfp);




    fseek(fp,sizeofheader+(section_number-2)*0x28,0);
    SECTION last_section;
    fread(&last_section,sizeof(SECTION),1,fp);
    DWORD section_pointer=last_section.PointerToRawData;
    DWORD section_size=last_section.SizeOfRawData;


    realloc(buf,0x28);
    SECTION new_section;
    memcpy(new_section.Name,".new",8);
    new_section.VirtualSize=0x100;
    new_section.VirtualAddress=0x7000;
    new_section.SizeOfRawData=0x200;
    new_section.PointerToRawData=last_section.PointerToRawData+last_section.SizeOfRawData;
    new_section.PointerToRelocations=0;
    new_section.PointerToLineNumbers=0;
    new_section.NumberOfRelocations=0;
    new_section.NumberOFLineNumbers=0;
    new_section.Characteristics=0x60000020;


    fwrite(&new_section,1,sizeof(last_section),outfp);

    int i=ftell(outfp);
    while(i%0x200!=0)
    {
        fputc(0x0,outfp);
        i++;
    }



    SECTION first_section;
    fseek(fp,sizeofheader,0);
    fread(&first_section,28,1,fp);

    /*fseek(fp,first_section.PointerToRawData,0);
    realloc(buf,last_section.PointerToRawData+last_section.SizeOfRawData-first_section.PointerToRawData);
    fread(buf,1,last_section.PointerToRawData+last_section.SizeOfRawData-first_section.PointerToRawData,fp);

    printf("%d",fseek(outfp,first_section.PointerToRawData,0));
    printf("%s",buf);
    fwrite(buf,1,last_section.PointerToRawData+last_section.SizeOfRawData-first_section.PointerToRawData,outfp);*/

    fseek(fp,first_section.PointerToRawData,0);
    BYTE c;
    c=fgetc(fp);
    while(!feof(fp))
    {

        fputc(c,outfp);
        c=fgetc(fp);
    }

    i=0;
    while(i<new_section.VirtualSize)
    {
        fputc(0xCC,outfp);
        i++;
    }
    while(i<new_section.SizeOfRawData)
    {
        fputc(0,outfp);
        i++;
    }


    DWORD imagesize;
    fseek(fp,e_lfanew+0x50,0);
    fread(&imagesize,4,1,fp);
    fseek(outfp,e_lfanew+0x50,0);
    imagesize+=0x1000;
    fwrite(&imagesize,4,1,outfp);

    DWORD jumpcode;
    fseek(outfp,new_section.PointerToRawData,0);
    jumpcode=first_section.VirtualAddress-new_section.VirtualAddress-5;
    char jmp=0xE9;
    fwrite(&jmp,1,1,outfp);
    fwrite(&jumpcode,4,1,outfp);

    fseek(outfp,e_lfanew+0x28,0);
    DWORD OEP;
    fwrite(&new_section.VirtualAddress,4,1,outfp);



    fclose(fp);
    fclose(outfp);


}
