#include <iostream>
#include <Windows.h>

LPVOID FeReadFile(const char* path) {
	DWORD bytesread = 0;
	HANDLE file   = CreateFileA(path, GENERIC_READ, FALSE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD filesz  = GetFileSize(file, NULL);
	LPVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, filesz);

	ReadFile(file,
		buffer,
		filesz,
		&bytesread,
		NULL);

	return buffer;
}

int PeParse(LPVOID buffer) {
	PIMAGE_DOS_HEADER ImageHeader		 = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS NtHeaders			 = (PIMAGE_NT_HEADERS)(ImageHeader->e_lfanew + (DWORD_PTR)buffer);
	IMAGE_FILE_HEADER FileHeader		 = NtHeaders->FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders->OptionalHeader;

	std::cout << "\n\n####################### [FILE HEADER] #######################\n\n";

	if (FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {

		std::cout << "[i] File Is : ";

		if (FileHeader.Characteristics & IMAGE_FILE_DLL)
			std::cout << "DLL \n";
		else if (FileHeader.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			std::cout << "SYS \n";
		else
			std::cout << "EXE \n";
	}

	if (FileHeader.Machine & IMAGE_FILE_32BIT_MACHINE) {
		std::cout << "[i] File Is : x86" << std::endl;
	}
	else {
		std::cout << "[i] File Is : x64" << std::endl;
	}

	std::cout << "\n\n####################### [OPTIONAL HEADERS] #######################\n\n";

	std::cout << "[i] Entry Point Address : 0x"		<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.AddressOfEntryPoint) << std::endl;
	std::cout << "[i] Size of code : "				<< (FLOAT)OptionalHeader.SizeOfCode << std::endl;
	std::cout << "[i] Size of Stack commited : "	<< OptionalHeader.SizeOfStackCommit << std::endl;
	std::cout << "[i] Size of Heap commited : "		<< OptionalHeader.SizeOfHeapCommit << std::endl;
	std::cout << "[i] .text section address : 0x"	<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.BaseOfCode) << std::endl;
	std::cout << "[i] .data section address : 0x"	<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.BaseOfData) << std::endl;

	std::cout << "\n\n####################### [DIRS] #######################\n\n";
	std::cout << "[i] IAT address : 0x"			<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) << std::endl;
	std::cout << "[i] EXPORTS address : 0x"		<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) << std::endl;
	std::cout << "[i] IMPORTS address : 0x"		<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) << std::endl;
	std::cout << "[i] RESOURCE address : 0x"	<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) << std::endl;
	std::cout << "[i] EXCEPTION address : 0x"	<< (PVOID)((DWORD_PTR)buffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress) << std::endl;

	std::cout << "\n\n####################### [SECTIONS] #######################\n\n";
	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)NtHeaders) + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
		printf("[#] %s \n", (CHAR*)pImgSectionHdr->Name);
		printf("\tSize : %d \n", pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pImgSectionHdr->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)((DWORD_PTR)buffer + pImgSectionHdr->VirtualAddress));
		printf("\tRelocations : %d \n", pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	return 1;
}

int main(int argc, char* argv[]) {
	for (int i = 1; i < argc; ++i) {
		PeParse(FeReadFile(argv[i]));
	}
}