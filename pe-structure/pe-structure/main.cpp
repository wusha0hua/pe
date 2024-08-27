#include"pe.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>




int main(int argc, char *argv[]) {
	/*
	if(argc != 2) {
		printf("%s <file>\n", argv[0]);
		exit(-1);
	}
	*/
	FILE *fp = fopen("pe.exe", "rb");
	fseek(fp, 0, SEEK_END);
	unsigned long len = ftell(fp);
	rewind(fp);

	char *pe_bytes = (char*)malloc(len);
	fread(pe_bytes, len, 1, fp);
	fclose(fp);
	
	Pe64 *pe64 = NULL;
	switch(PECheck::isPe(pe_bytes)) {
		case PE32: {

			}
			break;
		case PE64: 
			pe64 = new Pe64(pe_bytes);
			break;
		case UNKOWN:
			printf("%s unkwon type\n", argv[1]);
			exit(-1);
		case NOTPE:
			printf("%s is not a pe\n", argv[1]);
			exit(-1);
	}


}

