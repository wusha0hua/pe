#include"pe.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

PeType PECheck::isPe(char *pe_bytes) {
	IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER*)pe_bytes;
	
	if(image_dos_header->e_magic != 0x5a4d) {
		printf("%x\n", image_dos_header->e_magic);
		return NOTPE;
	}

	DWORD lfanew = image_dos_header->e_lfanew;
	if(pe_bytes[lfanew] != 'P' || pe_bytes[lfanew + 1] != 'E') {
		return NOTPE;
	}

	IMAGE_FILE_HEADER *image_file_header = (IMAGE_FILE_HEADER*)(pe_bytes + lfanew + 4);
	if(image_file_header->Machine == 0x014c) {
		return PE32;
	} else if(image_file_header->Machine == 0x8664) {
		return PE64;
	} else {
		return UNKOWN;
	}
}
