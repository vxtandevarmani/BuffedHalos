#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <psapi.h>

uint64_t fn1va(const char* data);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef NTSTATUS(NTAPI* NtContinue)(PCONTEXT ThreadContext, bool RaiseAlert);
typedef ULONG (NTAPI *pRtlNtStatusToDosError)(NTSTATUS);

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE			Reserved[4];
	VOID*			Reserved2[2];
	PPEB_LDR_DATA	LoaderData;
} PEB, * PPEB;


#define PATTERN_SIZE	2
#define STUB_SIZE 		24
#define FULL_STUB_SIZE	32
#define DWORD_MAX		0xFFFFFFFFUL


DWORD SyscallServiceNumber		= 0;
PDWORD SyscallAddressJmp		= NULL;
pRtlNtStatusToDosError LastErr	= NULL;

uint64_t fn1va(const char* data){
	uint64_t hash = 0xcbf29ce484222325;
	while(*(data + 1)){
		hash ^= *data++;
		hash *= 0x100000001b3;
	}
	return hash;
}

PBYTE grab_dll_ptr(uint64_t Hash){
	PLDR_DATA_TABLE_ENTRY Module	= NULL;
	PPEB PebStruct					= (PPEB)__readgsqword(0x60);
	char DllName[MAX_PATH];
	memset(DllName, 0, MAX_PATH);
	if(!PebStruct || !PebStruct->LoaderData){
		return NULL;
	}
	LIST_ENTRY* HeadDllList = PebStruct->LoaderData->InLoadOrderModuleList.Flink;
	while(HeadDllList != &PebStruct->LoaderData->InLoadOrderModuleList){
		Module = CONTAINING_RECORD(HeadDllList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if(!WideCharToMultiByte(CP_ACP, 0, Module->BaseDllName.Buffer, -1, DllName, MAX_PATH, NULL, NULL)){
			printf("[-] Failed to convert Wide to ANSI error code is %ld\n", GetLastError());
			return NULL;
		}
		if(fn1va(DllName) == Hash){
			return (PBYTE)(Module->DllBase);
		}
		HeadDllList = HeadDllList->Flink;
	}
	return NULL;
}

PBYTE grab_function_pointer(PBYTE Hmodule, uint64_t FunctionHash){
	PIMAGE_DOS_HEADER DosHeader				= (PIMAGE_DOS_HEADER)Hmodule;
	PIMAGE_NT_HEADERS NtHeader				= (PIMAGE_NT_HEADERS)(Hmodule + DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER FileHeader			= (PIMAGE_FILE_HEADER)(&NtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER OptionalHeader	= (PIMAGE_OPTIONAL_HEADER)((PBYTE)FileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_EXPORT_DIRECTORY ExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(Hmodule + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PWORD OrdinalTable		= (PWORD) (Hmodule + ExportDirectory->AddressOfNameOrdinals);
	PDWORD NameTable		= (PDWORD)(Hmodule + ExportDirectory->AddressOfNames);
	PDWORD AddressTable		= (PDWORD)(Hmodule + ExportDirectory->AddressOfFunctions);

	for(WORD i = 0; i < ExportDirectory->NumberOfNames; i++){
		char* Name = (char*)(Hmodule + NameTable[i]);
		if(fn1va(Name) == FunctionHash){
			return (Hmodule + AddressTable[OrdinalTable[i]]);
		}
	}
	return NULL;
}

void dynamic_ssn_retrieval(uint64_t FunctionHash, uint64_t CheckSum, PIMAGE_EXPORT_DIRECTORY ExportDirectory, PBYTE PeBase){
	PWORD OrdinalTable		= (PWORD)(PeBase + ExportDirectory->AddressOfNameOrdinals);
	PDWORD NameTable		= (PDWORD)(PeBase + ExportDirectory->AddressOfNames);
	PDWORD AddressTable		= (PDWORD)(PeBase + ExportDirectory->AddressOfFunctions);
	PDWORD AddressOfName	= NULL;

	bool found					= false;
	char CheckTest[STUB_SIZE]	= {0};

	for(WORD i = 0; i < ExportDirectory->NumberOfNames; i++){
		char* Name = (char*)(PeBase + NameTable[i]);
		if(fn1va(Name) == FunctionHash){
			AddressOfName = (PDWORD)(PeBase + AddressTable[OrdinalTable[i]]);			
			memcpy(CheckTest, AddressOfName, STUB_SIZE);
			memset(CheckTest + 4, 0, 4);
			printf("[+] Found function with name %s located at 0x%p\n", Name, (void*)(AddressOfName));
			if(fn1va(CheckTest) == CheckSum){
				SyscallServiceNumber	= *(PDWORD)((PBYTE)AddressOfName + 4);
				SyscallAddressJmp		=  (PDWORD)((PBYTE)AddressOfName + 18);
				printf("[+] Function is not hooked and the SSN is 0x%lx\n", SyscallServiceNumber);
				printf("[+] Found location of syscall opcode 0x%p\n", (void*)SyscallAddressJmp);
				return;
			}
			else{
				puts("[!] Function is hooked!");
				found = true;
				break;
			}
		}
	}
	if(!found){
		SyscallServiceNumber = DWORD_MAX;
		return;
	}
	PBYTE AddressUp		= NULL;
	PBYTE AddressDown	= NULL;
	for(DWORD i = 1; i < ExportDirectory->NumberOfFunctions; i++){
		// This is for checking lower SSNs or addresses above the hooked stub
		AddressUp = (PBYTE)AddressOfName - (i * FULL_STUB_SIZE);
		memcpy(CheckTest, AddressUp , STUB_SIZE);
		memset(CheckTest + 4, 0, 4);
		if(fn1va(CheckTest) == CheckSum){
			SyscallServiceNumber	= (*(PDWORD)(AddressUp + 4)) + i;
			SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			printf("[+] Found SSN 0x%lx via Halos Gate with negative delta of %ld\n", SyscallServiceNumber, i);
			printf("[+] Found location of unhooked syscall opcode 0x%p\n", (void*)SyscallAddressJmp);
			return;
		}
		// This is for checking higher SSNs or addresses below the hooked stub
		AddressDown = (PBYTE)AddressOfName + (i * FULL_STUB_SIZE);
		memcpy(CheckTest, AddressDown , STUB_SIZE);
		memset(CheckTest + 4, 0, 4);
		if(fn1va(CheckTest) == CheckSum){
			SyscallServiceNumber	= (*(PDWORD)(AddressDown + 4)) - i;
			SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			printf("[+] Found SSN 0x%lx via Halos Gate with positive delta of %ld\n", SyscallServiceNumber, i);
			printf("[+] Found location of unhooked syscall opcode 0x%p\n", (void*)SyscallAddressJmp);
			return;
		}
	}
	puts("[!] Every function is hooked!");
	SyscallServiceNumber = DWORD_MAX;
	return;
}

PDWORD pattern_scan(const char* pattern, HMODULE PeBase){
	MODULEINFO ModuleInfo = {0};
	if(!GetModuleInformation(GetCurrentProcess(), PeBase, &ModuleInfo, sizeof(ModuleInfo))){
		return NULL;
	}
	for(size_t i = 0; i < ModuleInfo.SizeOfImage - PATTERN_SIZE; i += PATTERN_SIZE){
		if(!memcmp(pattern, (PBYTE)PeBase + i, PATTERN_SIZE)){
			return (PDWORD)((PBYTE)PeBase + i);
		}
	}
	return NULL;
}

bool AnotherGate(DWORD SyscallServiceNumber, PDWORD SyscallAddressJmp, PDWORD JOPGadget, NtContinue NtCall){
	CONTEXT ctx = {0};
	ctx.ContextFlags = CONTEXT_ALL;
	RtlCaptureContext(&ctx);
	ctx.Rsp -= 8;

	LARGE_INTEGER interval;
	interval.QuadPart = -(1e7) * 12;

	printf("[*] Syscall stub for 0x%p\n", (void*)(DWORD64)SyscallAddressJmp);

	ctx.Rip = (DWORD64)JOPGadget;
	ctx.Rcx = (DWORD64)SyscallAddressJmp;
	ctx.Rax = (DWORD64)SyscallServiceNumber;

	ctx.R10 = (DWORD64)false;
	ctx.Rdx = (DWORD64)&interval;
	ctx.R8	= (DWORD64)0;
	ctx.R9	= (DWORD64)0;
	puts("[*] Calling NtContinue");
	
	NTSTATUS status = NtCall(&ctx, false);
	if(!NT_SUCCESS(status)){
		DWORD errorCode = LastErr(status);
		printf("[-] NtContinue failed: NTSTATUS 0x%08lX → Win32 Error %lu\n", status, errorCode);
		return -1;
	}
	RtlRestoreContext(&ctx, NULL);
	puts("[+] Successfully proxied syscall through NtContinue!");
	return true;
}

int main(void){
	const char JOPGadget[PATTERN_SIZE]	= { '\xff', '\xe1' };			 // jmp rcx		{'\x49', '\xff', '\xe2'};	// jmp r10
	const char SyscallStub[STUB_SIZE]	= {	'\x4c', '\x8b', '\xd1', 
											'\xb8', '\x00', '\x00', '\x00', '\x00', 
											'\xf6', '\x04', '\x25', '\x08', '\x03', '\xfe', '\x7f', '\x01', 
											'\x75', '\x03', 
											'\x0f', '\x05', 
											'\xc3', 
											'\xcd', '\x2e', 
											'\xc3'
	};
	const char NameNtDll[]					= {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\x00'};
	const char NameMsvcrt[]					= {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\x00'};

	const char NtContinueName[]				= {'N', 't', 'C', 'o', 'n', 't', 'i', 'n', 'u', 'e', '\x00'};
	const char RtlNtStatusToDosErrorName[]	= {'R', 't', 'l', 'N', 't', 'S', 't', 'a', 't', 'u', 's', 'T', 'o', 'D', 'o', 's', 'E', 'r', 'r', 'o', 'r', '\x00'};
	
	const char NtDelayExecutionName[]		= {'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', '\x00'};
	uint64_t CheckSum						= fn1va(SyscallStub);

	PBYTE NtdllBaseAddress					= grab_dll_ptr(fn1va(NameNtDll));
	if(!NtdllBaseAddress){
		puts("[-] Failed to Resolve PEB or base address of ntdll.dll");
		return -1;
	}
	else{
		printf("[+] Found ntdll.dll base address located at 0x%p\n", (PVOID)NtdllBaseAddress);
	}
	LastErr = (pRtlNtStatusToDosError)(uintptr_t)(grab_function_pointer(NtdllBaseAddress, fn1va(RtlNtStatusToDosErrorName)));
	if(!LastErr){
		puts("[-] Unable to resolve RtlNtStatusToDosError!");
		return -1;
	}
	else{
		printf("[+] Found RtlNtStatusToDosError located at %p\n", (void*)(uintptr_t)LastErr);
	}
	NtContinue NtCall = (NtContinue)(uintptr_t)(grab_function_pointer(NtdllBaseAddress, fn1va(NtContinueName)));
	if(!NtCall){
		puts("[-] Failed to resolve NtContinue!");
		return -1;
	}
	else{
		printf("[+] Resolved NtContinue located at address 0x%p\n", (void*)(uintptr_t)NtCall);
	}
	PBYTE MsvcrtBase = grab_dll_ptr(fn1va(NameMsvcrt));
	if(!MsvcrtBase){
		puts("[-] Unable to locate msvcrt.dll");
		return -1;
	}
	else{
		printf("[+] msvcrt.dll found at 0x%p\n", (void*)MsvcrtBase);
	}
	
	PIMAGE_DOS_HEADER DosHeader				= (PIMAGE_DOS_HEADER)NtdllBaseAddress;
	PIMAGE_NT_HEADERS NtHeader				= (PIMAGE_NT_HEADERS)(NtdllBaseAddress + DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER FileHeader			= (PIMAGE_FILE_HEADER)(&NtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER OptionalHeader	= (PIMAGE_OPTIONAL_HEADER)((PBYTE)FileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_EXPORT_DIRECTORY ExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(NtdllBaseAddress + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//pattern_scan(JOPGadget, (HMODULE)MsvcrtBase)
	PDWORD Jop = pattern_scan(JOPGadget, (HMODULE)NtdllBaseAddress);
	if(!Jop){
		puts("[-] Unable to locate JOP Gadgets!!");
		return -1;
	}
	else{
		printf("[+] JOP Gadget located at 0x%p\n", (void*)Jop);
	}
	//NtDelayExecutionName		-->		NtCreateFile
	dynamic_ssn_retrieval(fn1va(NtDelayExecutionName), CheckSum, ExportDirectory, NtdllBaseAddress);
	if(SyscallServiceNumber == DWORD_MAX || SyscallAddressJmp == NULL){
		puts("[-] Failed to retrieve SSN");
		return -1;
	}
	AnotherGate(SyscallServiceNumber, SyscallAddressJmp, Jop, NtCall);
	
	return 0;
}
// gcc src\main.c src\util.c -pedantic -Wall -Werror -o sol
