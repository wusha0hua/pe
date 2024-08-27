#include<windows/windows.h>

enum PeType {
	PE32, PE64, NOTPE, UNKOWN,
};

class PECheck {
public:
	static PeType isPe(char *pe_bytes);

};

typedef struct {
	IMAGE_DOS_HEADER *DosHeader;
	char *Stub;
	DWORD *Signatrue;
	IMAGE_FILE_HEADER *FileHeader;
	IMAGE_OPTIONAL_HEADER64 *OptionalHeader;
	IMAGE_SECTION_HEADER **SectionHeader;
	IMAGE_EXPORT_DIRECTORY **Export;
	IMAGE_IMPORT_DESCRIPTOR *Import;
	unsigned int ImportNum;
	IMAGE_THUNK_DATA64 **IAT, **INT;
	IMAGE_BASE_RELOCATION *Relaction;
	unsigned int RelocNum;
} PE64Struct;

class Pe64 {
private: 
	char *pe_bytes;
	PE64Struct *pe;	
public:

	Pe64(char *pe_bytes);
	
	unsigned long Vaddr2Offset(unsigned long long);
	unsigned long long Offset2Vaddr(unsigned long);
};
