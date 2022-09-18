#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <vector>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <sstream>
#include <winsock.h>
#include <chrono>
using std::ostringstream;
using std::ends;
#pragma comment(lib,"ws2_32.lib")

/*
Defining functions that are being hooked
  HANDLE CreateFileA(
  [in]           LPCSTR lpFileName,
  [in]           DWORD  dwDesiredAccess,
  [in]           DWORD  dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD dwCreationDisposition,
  [in]           DWORD dwFlagsAndAttributes,
  [in, optional] HANDLE hTemplateFile);

  LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
  );

  HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
  );

    LSTATUS RegOpenKeyExA(
    [in]           HKEY   hKey,
    [in, optional] LPCSTR lpSubKey,
    [in]           DWORD  ulOptions,
    [in]           REGSAM samDesired,
    [out]          PHKEY  phkResult
    );

    LSTATUS RegSetValueExA(
    [in]           HKEY       hKey,
    [in, optional] LPCSTR     lpValueName,
                 DWORD      Reserved,
   [in]           DWORD      dwType,
   [in]           const BYTE *lpData,
   [in]           DWORD      cbData
  );

    LSTATUS RegCreateKeyExA(
    [in]            HKEY                        hKey,
    [in]            LPCSTR                      lpSubKey,
                  DWORD                       Reserved,
    [in, optional]  LPSTR                       lpClass,
    [in]            DWORD                       dwOptions,
    [in]            REGSAM                      samDesired,
    [in, optional]  const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    [out]           PHKEY                       phkResult,
    [out, optional] LPDWORD                     lpdwDisposition
    );

    SOCKET WSAAPI socket(
    [in] int af,
    [in] int type,
    [in] int protocol
    );

    int WSAAPI connect(
    [in] SOCKET         s,
    [in] const sockaddr *name,
    [in] int            namelen
    );

*/

//char originalBytes[6];
std::map<const char*, void*> fnMap;
std::map<std::string, int> fnCounter;
std::vector<const char*> suspicious_functions = { "CreateFileA", "VirtualAlloc", "CreateThread", "RegOpenKeyExA", "RegSetValueExA", "RegCreateKeyExA", "socket", "connect" };
std::vector<FARPROC> addresses(8);
std::vector<char[6]> original(8);
std::map<const char*, int> function_index;
void SetInlineHook(LPCSTR lpProcName, const char* library, const char* funcName, int index);
HANDLE hFile;
std::chrono::steady_clock::time_point begin;

template<typename T>
void LOG(const char* message, T parameter) {


    WriteFile(hFile, message, strlen(message), NULL, nullptr);
    //WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
    ostringstream oss;
    oss << parameter << ends;
    WriteFile(hFile, oss.str().c_str(), strlen(oss.str().c_str()), NULL, nullptr);
    WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
}

struct HOOKING {
    static void __stdcall CreateFileAHook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

        LOG("\n----------intercepted call to CreateFileA----------\n\n", "");

        LOG("The name of the file or device to be created or opened is ", lpFileName);
        LOG("The requested access to the file or device ", dwDesiredAccess);
        LOG("The requested sharing mode of the file or device is ", dwShareMode);

        if (dwCreationDisposition == 2)
            LOG("An action to take on a file or device that exists or does not exist is ", "CREATE_ALWAYS");
        if (dwCreationDisposition == 1)
            LOG("An action to take on a file or device that exists or does not exist is ", "CREATE_NEW");
        if (dwCreationDisposition == 4)
            LOG("An action to take on a file or device that exists or does not exist is ", "OPEN_ALWAYS");
        if (dwCreationDisposition == 3)
            LOG("An action to take on a file or device that exists or does not exist is ", "OPEN_EXISTING");
        if (dwCreationDisposition == 5)
            LOG("An action to take on a file or device that exists or does not exist is ", "TRUNCATE_EXISTING");

        if (dwFlagsAndAttributes == 128)
            LOG("The Flags and Attributes that user is trying for the file are ", "NORMAL");
        if (dwFlagsAndAttributes == 16384)
            LOG("The Flags and Attributes that user is trying for the file are ", "ENCRYPTED");
        if (dwFlagsAndAttributes == 4096)
            LOG("The Flags and Attributes that user is trying for the file are ", "OFFLINE");
        if (dwFlagsAndAttributes == 2)
            LOG("The Flags and Attributes that user is trying for the file are ", "HIDDEN");
        if (dwFlagsAndAttributes == 256)
            LOG("The Flags and Attributes that user is trying for the file are ", "TEMPORARY");

        int index = function_index["CreateFileA"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to create a file is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to CreateFileA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        return SetInlineHook("CreateFileA", "kernel32.dll", "CreateFileAHook", index);
    }
    static void __stdcall VirtualAllocHook(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    {
        LOG("\n----------intercepted call to VirtualAlloc----------\n\n", "");

        LOG("The address the allocation is starting is at ", lpAddress);
        LOG("The size of the allocation is  ", dwSize);

        if (flAllocationType == 0x00001000)
            LOG("The type of memory allocation is ", "MEMORY COMMIT");
        if (flAllocationType == 0x00002000)
            LOG("The type of memory allocation is ", "MEMORY RESERVE");
        if (flAllocationType == 12288)
            LOG("The type of memory allocation is ", "MEMORY COMMIT AND MEMORY RESERVE");

        if (flProtect == 64)
            LOG("The memory protection for the region of pages to be allocated is ", "PAGE EXECUTING AND READWRITING");

        int index = function_index["VirtualAlloc"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to allocate memory is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to VirtualAlloc----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        return SetInlineHook("VirtualAlloc", "kernel32.dll", "VirtualAllocHook", index);
    }
    static void __stdcall CreateThreadHook(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
        LOG("\n----------intercepted call to CreateThread----------\n\n", "");

        LOG("The initial size of the stack, in bytes is ", dwStackSize);
        LOG("A pointer to the application-defined function to be executed by the thread ", lpStartAddress);
        LOG("A pointer to a variable to be passed to the thread is ", lpParameter);

        if (dwCreationFlags == 0)
            LOG("The thread runs immediately after creation", "");
        if (dwCreationFlags == 0x00000004)
            LOG("The thread is created in a suspended state", "");

        LOG("A pointer to a variable that receives the thread identifier", lpThreadId);

        int index = function_index["CreateThread"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to create a thread is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to CreateThread----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        return SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", index);
    }
    static void __stdcall RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {

        bool run_key = false;
        LOG("\n----------intercepted call to RegOpenKeyExA----------\n\n", "");
        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002))) {
            LOG("The key opened is ", "HKEY_LOCAL_MACHINE");
            if (std::string(lpSubKey) == std::string("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
                run_key = true;
        }

        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000001))) {
            LOG("The key opened is ", "HKEY_CURRENT_USER");
            if (std::string(lpSubKey) == std::string("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
                run_key = true;
        }


        LOG("The name of the registry subkey to be opened is ", lpSubKey);
        LOG("The option to apply when opening the key is ", ulOptions);

        if (samDesired == 0xF003F)
            LOG("A mask that specifies the desired access rights to the key to be opened is ", "KEY_ALL_ACCESS");

        int index = function_index["RegOpenKeyExA"];
        ++fnCounter[suspicious_functions[index]];

        //if ((hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000001)) || hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002))) &&
        //    lpSubKey == (LPCSTR)"Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
        //    LOG("\nExe probably trying to execute a file after every rebot through a Run key!!", "");
        //}

        LOG("The number of times user is trying to open a registry key is ", fnCounter[suspicious_functions[index]]);
        if (run_key)
            LOG("\nExe probably trying to execute a file after every rebot through a Run key!!", "");

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to RegOpenKeyExA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        return SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);

    }
    static void __stdcall RegSetValueExAHook(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {

        LOG("\n----------intercepted call to RegSetValueExA----------\n\n", "");
        LOG("The key opened is ", hKey);
        LOG("The name of the value to be set is ", lpValueName);
        if (dwType == 4ul)
            LOG("The type of data set is ", "REG_DWORD");
        if (dwType == 1ul)
            LOG("The type of data set is ", "REG_SZ");
        LOG("The data to be stored is ", lpData);

        int index = function_index["RegSetValueExA"];
        ++fnCounter[suspicious_functions[index]];

        LOG("The number of times user is trying to set a registry key is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to RegSetValueExA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
        return SetInlineHook("RegSetValueExA", "advapi32.dll", "RegSetValueExAHook", function_index["RegSetValueExA"]);
    }
    static void __stdcall RegCreateKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {

        LOG("\n----------intercepted call to RegCreateKeyExA----------\n\n", "");
        LOG("The key opened is ", hKey);
        LOG("The name of a subkey that this function opens or creates", lpSubKey);

        if (dwOptions == 0x00000000L)
            LOG("This key is not volatile", "");

        if (samDesired == 0xF003F)
            LOG("A mask that specifies the desired access rights to the key to be opened is ", "KEY_ALL_ACCESS");

        int index = function_index["RegCreateKeyExA"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to create a registry key is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to RegCreateKeyExA----------\n\n\n\n\n", "");


        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
        return SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);

    }
    static SOCKET __stdcall socketHook(int af, int type, int protocol) {

        LOG("\n----------intercepted call to socket----------\n\n", "");

        if (af == 2)
            LOG("The address family specification is ", "(IPv4) address family - AF_INET");

        if (type == 1)
            LOG("The type specification for the new socket is ", "TCP SOCK_STREAM");
        if (type == 2)
            LOG("The type specification for the new socket is ", "UDP SOCK_DGRAM");

        if (protocol == 1)
            LOG("The protocol to be used is ", "ICMP");
        if (protocol == 6)
            LOG("The protocol to be used is ", "TCP");
        if (protocol == 17)
            LOG("The protocol to be used is ", "UDP");

        int index = function_index["socket"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to create a socket is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to socket----------\n\n\n\n\n", "");


        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        SOCKET sock = socket(af, type, protocol);
        SetInlineHook("socket", "Ws2_32.dll", "socketHook", function_index["socket"]);
        return sock;

    }
    static int __stdcall connectHook(SOCKET s, const sockaddr* name, int namelen) {

        struct sockaddr_in* sin = (struct sockaddr_in*)name;
        uint16_t port;

        port = htons(sin->sin_port);
        char* ip = inet_ntoa((*sin).sin_addr);
        LOG("\n----------intercepted call to connect----------\n\n", "");
        LOG("The address socket is trying to connect to is ", ip);
        LOG("The port socket is using to connect is ", port);

        int index = function_index["connect"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to connect to another socket is ", fnCounter[suspicious_functions[index]]);
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        LOG("Time difference since attachment of hooks in [ns] is ", std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count());
        LOG("\n----------Done intercepting call to socket----------\n\n\n\n\n", "");


        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int r = connect(s, name, namelen);
        SetInlineHook("connect", "Ws2_32.dll", "connectHook", function_index["connect"]);
        return r;
    }
};

// we will jump to after the hook has been installed


// hooking logic
void SetInlineHook(LPCSTR lpProcName, LPCSTR library, const char* funcName, int index) {

    HINSTANCE hLib;
    VOID* myFuncAddress;
    CHAR patch[6] = { 0 };

    // get memory address of Hooked function
    hLib = LoadLibraryA(library);
    addresses[index] = (GetProcAddress(hLib, lpProcName));

    if (addresses[index] == NULL)
        return;

    // save the first 6 bytes into originalBytes (buffer)
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addresses[index], original[index], 6, NULL);

    // overwrite the first 6 bytes with a jump to myFunc
    myFuncAddress = fnMap[funcName];

    // create a patch "push <addr>, retn"
    // The push instruction pushes a 32bit value on the stack, and the retn instruction pops a 32bit address off the stack into the Instruction Pointer
    // meaning, when we push a function and return --> the ip will go straight to our function
    memcpy_s(patch, 1, "\x68", 1); // 0x68 opcode for push
    memcpy_s(patch + 1, 4, &myFuncAddress, 4);
    memcpy_s(patch + 5, 1, "\xC3", 1); // opcode for retn

    // write patch to the hookedAddress --> the Hooked function
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], patch, 6, NULL);
}

int main() {

    fnMap["CreateFileAHook"] = (void*)&HOOKING::CreateFileAHook;
    fnMap["VirtualAllocHook"] = (void*)&HOOKING::VirtualAllocHook;
    fnMap["CreateThreadHook"] = (void*)&HOOKING::CreateThreadHook;
    fnMap["RegOpenKeyExAHook"] = (void*)&HOOKING::RegOpenKeyExAHook;
    fnMap["RegSetValueExAHook"] = (void*)&HOOKING::RegSetValueExAHook;
    fnMap["RegCreateKeyExAHook"] = (void*)&HOOKING::RegCreateKeyExAHook;
    fnMap["socketHook"] = (void*)&HOOKING::socketHook;
    fnMap["connectHook"] = (void*)&HOOKING::connectHook;
    for (int i = 0; i < suspicious_functions.size(); i++)
    {
        fnCounter[suspicious_functions[i]] = 0;
        function_index[suspicious_functions[i]] = i;
    }

    hFile = CreateFile(L"LOG.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    //// Open a handle to the file                 
    //if (hFile == INVALID_HANDLE_VALUE)
    //{
    //    // Failed to open/create file
    //    return 2;
    //}
    //STARTUPINFO si;
    //PROCESS_INFORMATION pi;
    //ZeroMemory(&si, sizeof(si));
    //si.cb = sizeof(si);
    //ZeroMemory(&pi, sizeof(pi));
    //BOOL bSuccess = CreateProcess(L"virus.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    //if (bSuccess) {
    //    DWORD dwPid = GetProcessId(pi.hProcess);
    //    file = OpenProcess(MAXIMUM_ALLOWED | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid);
    //}

    SetInlineHook("CreateFileA", "kernel32.dll", "CreateFileAHook", function_index["CreateFileA"]);
    SetInlineHook("VirtualAlloc", "kernel32.dll", "VirtualAllocHook", function_index["VirtualAlloc"]);
    SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", function_index["CreateThread"]);
    SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);
    SetInlineHook("RegSetValueExA", "advapi32.dll", "RegSetValueExAHook", function_index["RegSetValueExA"]);
    SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);
    SetInlineHook("socket", "Ws2_32.dll", "socketHook", function_index["socket"]);
    SetInlineHook("connect", "Ws2_32.dll", "connectHook", function_index["connect"]);

    //HANDLE hFile = CreateFileA("evil.cpp",                // name of the write
    //    GENERIC_WRITE,          // open for writing
    //    0,                      // do not share
    //    NULL,                   // default security
    //    CREATE_NEW,             // create new file only
    //    FILE_ATTRIBUTE_NORMAL,  // normal file
    //    NULL);                  // no attr. template

    //if (!(hFile == INVALID_HANDLE_VALUE))
    //    printf("Could not open file\n");
    //else
    //    printf("Successfully opened file\n");

    //LPVOID address = VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    //hFile = CreateFileA("evil.txt",                // name of the write
    //    GENERIC_WRITE,          // open for writing
    //    0,                      // do not share
    //    NULL,                   // default security
    //    CREATE_NEW,             // create new file only
    //    FILE_ATTRIBUTE_NORMAL,  // normal file
    //    NULL);                  // no attr. template

    //if (!(hFile == INVALID_HANDLE_VALUE))
    //    printf("Could not open file\n");
    //else
    //    printf("Successfully opened file\n");

    //address = VirtualAlloc(NULL, 11, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);
    //CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);

    //HKEY key;
    //HKEY new_key;
    //DWORD disable = 1;
    //LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
    //RegSetValueExA(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    //RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
    //ResumeThread(pi.hThread);
    //CloseHandle(pi.hThread);
    //CloseHandle(file);
    //myfile.close();

    return 0;
}

BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) // Reserved
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // A process is loading the DLL.
        begin = std::chrono::steady_clock::now();
        main();
    case DLL_THREAD_ATTACH:
        // A process is creating a new thread.
        break;
    case DLL_THREAD_DETACH:
        // A thread exits normally.
        break;
    case DLL_PROCESS_DETACH:
        // A process unloads the DLL.
        break;
    }
    return TRUE;
}
