#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <system_error>
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    KPRIORITY               BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
    ULONG                   HandleCount;
    ULONG                   Reserved2[2];
    ULONG                   PrivatePageCount;
    IO_COUNTERS             IoCounters;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

void DisplayError(DWORD NTStatusMessage);

int main()
{
    HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
    if (!hNtDll) {
        std::cerr << "Error: Failed to load ntdll.dll. Error Code: " << GetLastError() << std::endl;
        return -1;
    }

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        std::cerr << "Error: Failed to locate NtQuerySystemInformation. Error Code: " << GetLastError() << std::endl;
        FreeLibrary(hNtDll);
        return -1;
    }

    NTSTATUS status;
    PVOID buffer;
    PSYSTEM_PROCESS_INFO ptr;

    buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        std::cerr << "Error: VirtualAlloc failed! Error Code: " << GetLastError() << std::endl;
        return -1;
    }

    std::cout << "Process list allocated at address: " << buffer << std::endl;
    ptr = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer);

    if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, ptr, 1024 * 1024, NULL)))
    {
        DisplayError(status);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return -1;
    }

    while (ptr->NextEntryOffset)
    {
        std::wcout << L"Process name : " << (ptr->ImageName.Buffer ? ptr->ImageName.Buffer : L"(Unnamed)") << L" | Process ID : " << static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ptr->ProcessId)) << std::endl;
        ptr = (PSYSTEM_PROCESS_INFO)((LPBYTE)ptr + ptr->NextEntryOffset);
    }

    std::cout << "Press any key to continue." << std::endl;
    std::cin.get();

    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

void DisplayError(DWORD NTStatusMessage) {
    LPVOID lpMessageBuffer = nullptr;
    HMODULE hModule = LoadLibrary(L"NTDLL.DLL");

    if (!hModule) {
        std::cerr << "Failed to load NTDLL.DLL. Error: " << GetLastError() << std::endl;
        return;
    }

    DWORD dwFormatResult = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_FROM_HMODULE,
        hModule,
        NTStatusMessage,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMessageBuffer,
        0,
        NULL);

    if (dwFormatResult == 0) {
        std::cerr << "Failed to retrieve error message. Error: " << GetLastError() << std::endl;
    }
    else {
        std::wcout << L"NTSTATUS Error: " << (LPCWSTR)lpMessageBuffer << std::endl;
    }

    if (lpMessageBuffer) {
        LocalFree(lpMessageBuffer);
    }
    FreeLibrary(hModule);
}