#include<stdio.h>
#include<windows.h>

int main()
{
    char FilePath[]="U:\\doc\\system\\windows\\hello.exe";

    FILE *fp=fopen(FilePath,"rb");

    IMAGE_DOS_HEADER DosHeader;
    fread(&DosHeader,sizeof(IMAGE_DOS_HEADER),1,fp);

    fseek(fp,DosHeader.e_lfanew,0);
    IMAGE_NT_HEADERS32 NTHeader;
    fread(&NTHeader,sizeof(IMAGE_NT_HEADERS32),1,fp);

    IMAGE_DATA_DIRECTORY Import=NTHeader.OptionalHeader.DataDirectory[1];

    DWORD NumberOfSections=NTHeader.FileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER *SectionHeader=new IMAGE_SECTION_HEADER[NumberOfSections];

    fseek(fp,DosHeader.e_lfanew+sizeof(NTHeader),0);
    fread(SectionHeader,sizeof(IMAGE_SECTION_HEADER),NumberOfSections,fp);

    int i=0;
    while(i<NumberOfSections)
    {
        if(*(DWORD*)&Import>SectionHeader[i].VirtualAddress&&*(DWORD*)&Import<(SectionHeader[i].VirtualAddress+*(DWORD*)&SectionHeader[i].Misc))
        {
            break;
        }
        i++;
    }

    fseek(fp,*(DWORD*)&Import-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
    IMAGE_IMPORT_DESCRIPTOR IID;
    fread(&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),1,fp);
    int j=1;
    int k=1;
    char Name[100];
    IMAGE_THUNK_DATA32 INT,IAT;
    IMAGE_IMPORT_BY_NAME IIBN;
    while(IID.OriginalFirstThunk!=0)
    {
        
        printf("\n%d:\n",j);
        printf("OriginalFirstThunk:%X\n",IID.OriginalFirstThunk);
        fseek(fp,IID.Name-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
        fgets(Name,200,fp);
        printf("Name:%s\n",Name);
        printf("FirstThunk:%X\n",IID.FirstThunk);

        printf("INT:\n");
        fseek(fp,IID.OriginalFirstThunk-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
        fread(&INT,sizeof(IMAGE_THUNK_DATA32),1,fp);
        k=1;
        while(*(DWORD*)&INT.u1!=0)
        {
            printf("RVA:%X\n",INT.u1);
            fseek(fp,*(DWORD*)&INT.u1-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
            fread(&IIBN,sizeof(IMAGE_IMPORT_BY_NAME),1,fp);
            printf("Hint:%X\n",IIBN.Hint);
            fseek(fp,*(DWORD*)&INT.u1-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData+2,0);
            fgets(Name,200,fp);
            printf("Name:%s\n",Name);

            
            fseek(fp,IID.OriginalFirstThunk-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData+sizeof(IMAGE_THUNK_DATA32)*k,0);
            fread(&INT,sizeof(IMAGE_THUNK_DATA32),1,fp);

            k++;
            printf("\n");
        }

        printf("IAT:\n");
        fseek(fp,IID.FirstThunk-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
        fread(&IAT,sizeof(IMAGE_THUNK_DATA32),1,fp);
        k=1;
        while(*(DWORD*)&IAT.u1!=0)
        {
            printf("RVA:%X\n",IAT.u1);
            fseek(fp,*(DWORD*)&IAT.u1-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData,0);
            fread(&IIBN,sizeof(IMAGE_IMPORT_BY_NAME),1,fp);
            printf("Hint:%X\n",IIBN.Hint);
            fseek(fp,*(DWORD*)&IAT.u1-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData+2,0);
            fgets(Name,200,fp);
            printf("Name:%s\n",Name);

            
            fseek(fp,IID.FirstThunk-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData+sizeof(IMAGE_THUNK_DATA32)*k,0);
            fread(&IAT,sizeof(IMAGE_THUNK_DATA32),1,fp);

            k++;
            printf("\n");
        }


        fseek(fp,*(DWORD*)&Import-SectionHeader[i].VirtualAddress+SectionHeader[i].PointerToRawData+sizeof(IMAGE_IMPORT_DESCRIPTOR)*j,0);
        fread(&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),1,fp);
        j++;
        printf("-----------------------------------------------\n");
    }


    fclose(fp);
}