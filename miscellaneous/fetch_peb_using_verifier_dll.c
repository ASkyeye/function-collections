/*

    This module uses VerifierDestroyRpcPageHeap() from verifier.dll to fetch PEB address

    Tested on: Windows 11 24H2
    Author: @whokilleddb

*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define SEARCH_LIMIT 20			// How many bytes to search
#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)
#define UNUSED(x) (void)(x)
#define ERR_PRINT(x) printf("[-] %s() failed with error: 0x%lx\n", x, GetLastError())

PPEB g_ppeb = NULL;
LPVOID g_move_qs_word_addr = NULL;
LPVOID g_next_inst_addr = NULL;

//How normal people would read PEB
PPEB NormalWayOfReadingPEB() {
	PPEB ppeb = (PPEB)__readgsqword(0x60);
	printf("[+] PEB is at:\t0x%p\n", ppeb);
	return ppeb;
}

// VEH magic for us
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ||
		ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		// Check if we are at the *next instruction
		if (ExceptionInfo->ContextRecord->Rip == (DWORD64)g_next_inst_addr)
		{
			// RAX has the PPEB due to the previous instruction
			g_ppeb = (LPVOID)ExceptionInfo->ContextRecord->Rax;

			printf("[+] Exception caught at target address:\t\t0x%p\n", g_next_inst_addr);
			printf("[+] RAX value captured:\t\t\t\t0x%p\n", g_ppeb);

			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

long CALLBACK ehandler(EXCEPTION_POINTERS *pointers) {
	UNUSED(pointers);
	return EXCEPTION_EXECUTE_HANDLER;
}

void PsychoPathWayOfReadingPEB() {
	if (g_ppeb) {
		printf("[+] PEB already located at:\t0x%p\n", g_ppeb);
		return;
	}

	// Add VEH
	PVOID hVeh = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
	if (hVeh == NULL)
	{
		ERR_PRINT("AddVectoredException");
		return;
	}

	HMODULE hVerifier = LoadLibraryA("verifier.dll");
	if (hVerifier == NULL) {
		ERR_PRINT("LoadLibraryA");
		return;
	}

	LPVOID VerifierDestroyRpcPageHeap = (LPVOID)GetProcAddress(hVerifier, "VerifierDestroyRpcPageHeap");
	if (VerifierDestroyRpcPageHeap == NULL) {
		ERR_PRINT("GetProcAddress");
		return;
	}

	printf("\n[+] VerifierDestroyRpcPageHeap() located at:\t0x%p\n", VerifierDestroyRpcPageHeap);
	for (DWORD i = 0; i < SEARCH_LIMIT; i++) {
		if ( 
			((BYTE*)VerifierDestroyRpcPageHeap)[i] == 0x65 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 1] == 0x48 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 2] == 0x8b &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 3] == 0x04 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 4] == 0x25 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 5] == 0x60 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 6] == 0x00 &&
			((BYTE*)VerifierDestroyRpcPageHeap)[i + 7] == 0x00 &&
			((WORD*)VerifierDestroyRpcPageHeap)[i + 3] == 0
			) {
			g_move_qs_word_addr = RVA2VA(LPVOID, VerifierDestroyRpcPageHeap, i);
			g_next_inst_addr = RVA2VA(LPVOID, VerifierDestroyRpcPageHeap, i + 9);
		}
	}

	if (g_move_qs_word_addr == NULL) {
		printf("[-] Could not locate opcode\n");
		return;
	}

	printf("[+] Target Opcode Found out at:\t\t\t0x%p\n", g_move_qs_word_addr);

	// Set HWBP
	CONTEXT ctx = { 0 };
	CONTEXT orig_ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext((HANDLE)-2, &ctx))
	{
		ERR_PRINT("GetThreadContext");
		return;
	}

	// Copy original thread context
	memcpy(&orig_ctx, &ctx, sizeof(CONTEXT));
	
	// Set DR0 to our target address
	ctx.Dr0 = (DWORD64)g_next_inst_addr;

	// Enable DR0 for execution breakpoint
	ctx.Dr7 |= 0x00000001;  // Enable DR0
	ctx.Dr7 |= 0x00000000;  // Break on execution (00 in bits 16-17)
	ctx.Dr7 &= (DWORD64)~0x00030000; // Clear size bits for DR0 (execution breakpoints ignore size)

	if (!SetThreadContext((HANDLE)-2, &ctx))
	{
		ERR_PRINT("SetThreadContext");
		return;
	}
    __try1 (ehandler) {
		((void (*)())g_move_qs_word_addr)();

	}
	__except1 {
		printf("[+] PEB is at:\t0x%p\n", g_ppeb);
		
	}

	if (!SetThreadContext((HANDLE)-2, &orig_ctx))
	{
		ERR_PRINT("SetThreadContext");
		return;
	}

	RemoveVectoredExceptionHandler(hVeh);

}

int main() {
	PPEB n_peb = NormalWayOfReadingPEB();
	PsychoPathWayOfReadingPEB();

	if (n_peb == g_ppeb) {
		printf("\n[+] PEB addresses match up!");
	} else {
		printf("\n[-] PEB addresses do not match up!");
	}
	return 0;
}
