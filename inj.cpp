#include <iostream>
#include <windows.h>
#include "pch.h"


int main()
{

    const char name[] = { "inline.dll" };
    unsigned int len{ sizeof(name) + 1 };
    DWORD result = GetFullPathNameA(name, 0, NULL, NULL);
    char* buf = new char[result];
    result = GetFullPathNameA(name, result, buf, NULL);

    PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

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

    PVOID memAddr = (PVOID)VirtualAllocEx(
        pi.hProcess,
        NULL,
        result,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (memAddr == NULL) {
        DWORD err = GetLastError();
        std::cout << err;
        return 0;
    }

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
    return 0;
}