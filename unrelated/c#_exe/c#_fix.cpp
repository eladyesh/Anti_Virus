#include <windows.h>
#include "pch.h"
#include <sstream>
using std::ostringstream;
using std::ends;
#pragma comment(lib,"ws2_32.lib")
#pragma comment (lib, "user32.lib")

HANDLE hFile;
void setMySuperHook();
void setMyDeleteAHook();

template<typename T>
void LOG(const char* message, T parameter) {

    WriteFile(hFile, message, strlen(message), NULL, nullptr);
    //WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
    ostringstream oss;
    oss << parameter << ends;
    WriteFile(hFile, oss.str().c_str(), strlen(oss.str().c_str()), NULL, nullptr);
    WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
}

// buffer for saving original bytes
char originalBytes[6]; char originalDeleteAddress[6];

FARPROC hookedAddress; FARPROC hookedDeleteAddress;

// we will jump to after the hook has been installed
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

    LOG("\n----------Done intercepting call to CreateFileA----------\n\n\n\n\n", "");

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 6, NULL);
    CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return setMySuperHook();
}
static int __stdcall DeleteFileAHook(LPCSTR lpFileName) {

    LOG("\n----------intercepted call to DeleteFileA----------\n\n", "");
    LOG("The path to the file that is to be deleted is ", lpFileName);

    LOG("\n----------Done intercepting call to DeleteFileA----------\n\n\n\n\n", "");
    
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedDeleteAddress, originalDeleteAddress, 6, NULL);
    int success = DeleteFileA(lpFileName);
    setMyDeleteAHook();
    return success;
}
// hooking logic
void setMySuperHook() {

    HINSTANCE hLib;
    VOID* myFuncAddress;
    DWORD* rOffset;
    DWORD* hookAddress;
    DWORD src;
    DWORD dst;
    CHAR patch[6] = { 0 };

    // get memory address of function WinExec
    hLib = LoadLibraryA("kernel32.dll");
    hookedAddress = GetProcAddress(hLib, "CreateFileA");

    myFuncAddress = &CreateFileAHook;
    // save the first 6 bytes into originalBytes (buffer)
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hookedAddress, originalBytes, 6, NULL);

    // overwrite the first 6 bytes with a jump to myFunc

    // create a patch "push <addr>, retn"
    memcpy_s(patch, 1, "\x68", 1); // 0x68 opcode for push
    memcpy_s(patch + 1, 4, &myFuncAddress, 4);
    memcpy_s(patch + 5, 1, "\xC3", 1); // opcode for retn

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, patch, 6, NULL);
}
void setMyDeleteAHook() {
    HINSTANCE hLib;
    VOID* myFuncAddress;
    DWORD* rOffset;
    DWORD* hookAddress;
    DWORD src;
    DWORD dst;
    CHAR patch[6] = { 0 };

    // get memory address of function WinExec
    hLib = LoadLibraryA("kernel32.dll");
    hookedDeleteAddress = GetProcAddress(hLib, "DeleteFileA");

    // save the first 6 bytes into originalBytes (buffer)
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hookedDeleteAddress, originalDeleteAddress, 6, NULL);

    // overwrite the first 6 bytes with a jump to myFunc
    myFuncAddress = &DeleteFileAHook;

    // create a patch "push <addr>, retn"
    memcpy_s(patch, 1, "\x68", 1); // 0x68 opcode for push
    memcpy_s(patch + 1, 4, &myFuncAddress, 4);
    memcpy_s(patch + 5, 1, "\xC3", 1); // opcode for retn

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedDeleteAddress, patch, 6, NULL);
}

int main()
{
    hFile = CreateFile(L"LOG.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    setMySuperHook();
    setMyDeleteAHook();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  nReason, LPVOID lpReserved) {
    switch (nReason) {
    case DLL_PROCESS_ATTACH:
        main();
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}