#include <iostream>
#include <windows.h>
#include "pch.h"


int main()
{
    /**
     * Main function that executes the code.
     * @return 0 indicating successful execution.
     */

    // Name of the DLL file
    const char name[] = { "inline.dll" };
    unsigned int len{ sizeof(name) + 1 };

    // Get the full path of the DLL file
    DWORD result = GetFullPathNameA(name, 0, NULL, NULL);
    char* buf = new char[result];
    result = GetFullPathNameA(name, result, buf, NULL);

    // Get the address of the LoadLibraryA function
    PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

    // Create a new process
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA(
        "virus.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        (LPSTARTUPINFOA)&si,
        &pi
    );

    // Allocate memory in the remote process
    PVOID memAddr = (PVOID)VirtualAllocEx(
        pi.hProcess,
        NULL,
        result,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    // Check if memory allocation was successful
    if (memAddr == NULL) {
        DWORD err = GetLastError();
        std::cout << err;
        int x;
        std::cin >> x;
        return 0;
    }

    // Write the DLL file path to the remote process
    if (!WriteProcessMemory(
        pi.hProcess,
        memAddr,
        buf,
        result,
        NULL
    )) {
        DWORD err = GetLastError();
        std::cout << err;
        return 0;
    }

    // Create a remote thread in the remote process to load the DLL
    HANDLE remote_thread = CreateRemoteThread(
        pi.hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)addrLoadLibrary,
        memAddr,
        0,
        NULL
    );
    WaitForSingleObject(remote_thread, INFINITE);
    CloseHandle(remote_thread);

    CreateProcessA(
        "HookForWrite.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        (LPSTARTUPINFOA)&si,
        &pi
    );

    return 0;
}