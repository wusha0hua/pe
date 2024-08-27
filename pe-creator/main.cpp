#include"creator.h"
#include<windows/windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>


IMAGE_DOS_HEADER *initDosHeader();
IMAGE_NT_HEADERS64 *initNtHeader();
IMAGE_OPTIONAL_HEADER64 *initOptionalHeader();

char stub[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10};
int main() {
	FILE *fp = fopen("output.exe", "wb");
	FILE *fcode = fopen("code", "rb");
	fseek(fcode, 0, SEEK_END);
	unsigned int code_size = ftell(fcode);
	rewind(fcode);
	char *code = (char*)malloc(code_size);
	fread(code, code_size, 1, fcode);

	IMAGE_DOS_HEADER *dos_header = initDosHeader();	
	IMAGE_NT_HEADERS64 *nt_header = initNtHeader();
	
	IMAGE_SECTION_HEADER *code_section = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(code_section, 0, code_size);
	code_section->SizeOfRawData = 0x200;
	memcpy(code_section->Name, ".text", 8);
	code_section->VirtualAddress = 0x1000;
	code_section->Misc.VirtualSize = code_size;
	code_section->Characteristics = 0x80000000;

	unsigned int lfanew = sizeof(IMAGE_DOS_HEADER) + sizeof(stub);
	dos_header->e_lfanew = lfanew;

	fwrite(dos_header, sizeof(IMAGE_DOS_HEADER), 1, fp);
	fwrite(stub, sizeof(stub), 1, fp);
	fwrite(nt_header, sizeof(IMAGE_NT_HEADERS64), 1, fp);
	unsigned int code_section_offset = ftell(fp);
	fwrite(code_section, sizeof(IMAGE_SECTION_HEADER), 1, fp);	
	
	unsigned int offset = ftell(fp);
	unsigned int code_offset = offset;
	if(offset % nt_header->OptionalHeader.FileAlignment != 0) {
		code_offset = ((code_offset / nt_header->OptionalHeader.FileAlignment) + 1) * nt_header->OptionalHeader.FileAlignment;
		char *dump = (char*)malloc(code_offset - offset);
		memset(dump, 0, code_offset - offset);
		fwrite(dump, code_offset - offset, 1, fp);
	}

	fwrite(code, code_size, 1, fp);
	offset = ftell(fp);
	while(offset % nt_header->OptionalHeader.FileAlignment != 0) {
		putc(0, fp);
		offset++;
	}

	code_section->PointerToRawData = code_offset;
	fseek(fp, 0, SEEK_SET);
	fwrite(code_section, sizeof(IMAGE_SECTION_HEADER), 1, fp);


}

IMAGE_DOS_HEADER *initDosHeader() {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	memset(dos_header, 0, sizeof(IMAGE_DOS_HEADER));
	dos_header->e_magic = 0x5a4d;

	return dos_header;
}

IMAGE_NT_HEADERS64 *initNtHeader() {
	IMAGE_NT_HEADERS64 *nt_header = (IMAGE_NT_HEADERS64*)malloc(sizeof(IMAGE_NT_HEADERS64));
	memset(nt_header, 0, sizeof(IMAGE_NT_HEADERS64));

	nt_header->Signature = 0x4550;

	nt_header->FileHeader.Machine = IMAGE_FILE_MACHINE_IA64;
	nt_header->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
	nt_header->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
	nt_header->FileHeader.NumberOfSections = 1;
	nt_header->FileHeader.NumberOfSymbols = 0;

	
	nt_header->OptionalHeader.Magic = 0x020b;
	nt_header->OptionalHeader.FileAlignment = 0x200;
	nt_header->OptionalHeader.SectionAlignment = 0x1000;
	nt_header->OptionalHeader.ImageBase = 0x401000;
	nt_header->OptionalHeader.SizeOfCode = 0x200;
	nt_header->OptionalHeader.AddressOfEntryPoint = 0x1000;
	nt_header->OptionalHeader.SizeOfImage = 0x1000;
	nt_header->OptionalHeader.SizeOfHeaders = 0x200;



	return nt_header;
}

IMAGE_OPTIONAL_HEADER64 *initOptionalHeader() {
	IMAGE_OPTIONAL_HEADER64 *optional_header = (IMAGE_OPTIONAL_HEADER64*)malloc(sizeof(IMAGE_OPTIONAL_HEADER64));
	memset(optional_header, 0, sizeof(IMAGE_OPTIONAL_HEADER64));
	

	return optional_header;
}
