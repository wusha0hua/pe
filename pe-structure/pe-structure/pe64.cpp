#include"pe.h"

#include <cstdlib>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

Pe64::Pe64(char *pe_bytes) {
	this->pe_bytes = pe_bytes;
	this->pe = (PE64Struct*)malloc(sizeof(PE64Struct));	

	this->pe->DosHeader = (IMAGE_DOS_HEADER*)pe_bytes;

	pe->Signatrue = (DWORD*)(this->pe_bytes + pe->DosHeader->e_lfanew);
	pe->FileHeader = (IMAGE_FILE_HEADER*)((char*)pe->Signatrue + sizeof(DWORD));
	pe->OptionalHeader = (IMAGE_OPTIONAL_HEADER64*)((char*)pe->FileHeader + sizeof(IMAGE_FILE_HEADER));

	pe->SectionHeader = (IMAGE_SECTION_HEADER**)malloc(sizeof(IMAGE_SECTION_HEADER*) * pe->FileHeader->NumberOfSections);
		
	for(int i = 0; i < pe->FileHeader->NumberOfSections; i++) {
		pe->SectionHeader[i] = (IMAGE_SECTION_HEADER*)((char*)pe->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER64) + i * sizeof(IMAGE_SECTION_HEADER));
	}

	if(pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0) {
		int num = pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size / sizeof(IMAGE_EXPORT_DIRECTORY);
		pe->Export = (IMAGE_EXPORT_DIRECTORY**)malloc(sizeof(IMAGE_EXPORT_DIRECTORY*) * num);	
		unsigned int first_export_vaddr = pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		unsigned int first_export_offset = this->Vaddr2Offset(first_export_vaddr);
		for(int i = 0; i < num; i++) {
			pe->Export[i] = (IMAGE_EXPORT_DIRECTORY*)((char*)this->pe_bytes + first_export_offset + i * sizeof(IMAGE_EXPORT_DIRECTORY));
		}
	} else {
		pe->Export = NULL;
	}

	
	if(pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		int num = pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		DWORD vaddr = pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		unsigned int offset = this->Vaddr2Offset(vaddr);
		unsigned intfirst_import_offset = offset;
		this->pe->Import = (IMAGE_IMPORT_DESCRIPTOR*)(this->pe_bytes + offset);
		char *zero = (char*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
		memset(zero, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		for(int i = 0;; i++) {
			if(memcmp(&this->pe->Import[i], zero, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0) {
				this->pe->ImportNum = i;	
				break;
			}
		}
	}

	this->pe->IAT = (IMAGE_THUNK_DATA64**)malloc(sizeof(IMAGE_THUNK_DATA64*) * this->pe->ImportNum);
	this->pe->INT = (IMAGE_THUNK_DATA64**)malloc(sizeof(IMAGE_THUNK_DATA64*) * this->pe->ImportNum);
	
	for(int i = 0; i < this->pe->ImportNum; i++) {
		this->pe->INT[i] = (IMAGE_THUNK_DATA64*)(this->pe_bytes + this->Vaddr2Offset(this->pe->Import[i].OriginalFirstThunk));
		this->pe->IAT[i] = (IMAGE_THUNK_DATA64*)(this->pe_bytes + this->Vaddr2Offset(this->pe->Import[i].FirstThunk));
	
		//printf("%x\n", this->pe->IAT[i]->u1);
		//printf("%x\n", this->pe->INT[i]->u1);

		IMAGE_IMPORT_BY_NAME *import_by_name = (IMAGE_IMPORT_BY_NAME*)(this->pe_bytes + this->Vaddr2Offset(this->pe->IAT[i]->u1.AddressOfData));

	}	

	if(this->pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0) {
		unsigned int vaddr = this->pe->OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;		
		unsigned int offset = this->Vaddr2Offset(vaddr);
		this->pe->Relaction = (IMAGE_BASE_RELOCATION*)(this->pe_bytes + offset);
		for(int i = 0;; i++) {
		}
	}
		
}

unsigned long Pe64::Vaddr2Offset(unsigned long long vaddr) {
	DWORD FileAlign = this->pe->OptionalHeader->FileAlignment;
	DWORD SectionAlign = this->pe->OptionalHeader->SectionAlignment;
	unsigned long long section_vaddr = 0;
	unsigned int section_offset = 0;
	for(int i = 0; i < this->pe->FileHeader->NumberOfSections; i++) {
		if(this->pe->SectionHeader[i]->VirtualAddress <= vaddr && vaddr < this->pe->SectionHeader[i]->VirtualAddress + this->pe->SectionHeader[i]->Misc.VirtualSize) {
			section_vaddr = this->pe->SectionHeader[i]->VirtualAddress;
			section_offset = this->pe->SectionHeader[i]->PointerToRawData;
			break;
		}
	}

	if(section_vaddr == 0 || section_offset == 0) {
		return 0;
	}
	
	return (vaddr - section_vaddr) + section_offset;
}

unsigned long long Pe64::Offset2Vaddr(unsigned long offset) {
	DWORD FileAlign = this->pe->OptionalHeader->FileAlignment;
	DWORD SectionAlign = this->pe->OptionalHeader->SectionAlignment;
	unsigned int section_offset = 0;
	unsigned int section_vaddr = 0;
	for(int i = 0; i < this->pe->FileHeader->NumberOfSections; i++) {
		if(this->pe->SectionHeader[i]->PointerToRawData <= offset && offset < this->pe->SectionHeader[i]->PointerToRawData + this->pe->SectionHeader[i]->SizeOfRawData) {
			section_vaddr = this->pe->SectionHeader[i]->VirtualAddress;
			section_offset = this->pe->SectionHeader[i]->PointerToRawData;
			break;
		}
	}

	if(section_vaddr == 0 || section_offset == 0) {
		return 0;
	}
	
	return (offset - section_offset) + section_vaddr;
}
