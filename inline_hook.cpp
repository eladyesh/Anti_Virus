#include <windows.h>
#include <iostream>
#include <map>
#define LOG(message, parameter) { std::cout << message << parameter << std::endl;}

/*

Defining functions that are being hooked

HANDLE CreateFileA(
  [in]           LPCSTR lpFileName,
  [in]           DWORD  dwDesiredAccess,
  [in]           DWORD  dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD dwCreationDisposition,
  [in]           DWORD dwFlagsAndAttributes,
  [in, optional] HANDLE hTemplateFile

);*/

// buffer for saving original bytes
char originalBytes[6];
std::map<const char*, void*> fnMap;
FARPROC hookedAddress;

// we will jump to after the hook has been installed
HANDLE __stdcall CreateFileAHook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    LOG("The name of the file or device to be created or opened is ", lpFileName);
    LOG("The requested access to the file or device ", dwDesiredAccess);
    LOG("The requested sharing mode of the file or device is ", dwShareMode);

    if(dwCreationDisposition == 2)
        LOG("An action to take on a file or device that exists or does not exist is ", "CREATE_ALWAYS");
    if (dwCreationDisposition == 1)
        LOG("An action to take on a file or device that exists or does not exist is ", "CREATE_NEW");
    if (dwCreationDisposition == 4)
        LOG("An action to take on a file or device that exists or does not exist is ", "OPEN_ALWAYS");
    if (dwCreationDisposition == 3)
        LOG("An action to take on a file or device that exists or does not exist is ", "OPEN_EXISTING");
    if (dwCreationDisposition == 5)
        LOG("An action to take on a file or device that exists or does not exist is ", "TRUNCATE_EXISTING");

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 6, NULL);
    return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// hooking logic
void SetInlineHook(LPCSTR lpProcName, const char* funcName) {
    HINSTANCE hLib;
    VOID* myFuncAddress;
    DWORD* rOffset;
    DWORD* hookAddress;
    DWORD src;
    DWORD dst;
    CHAR patch[6] = { 0 };

    // get memory address of function WinExec
    hLib = LoadLibraryA("kernel32.dll");
    hookedAddress = GetProcAddress(hLib, lpProcName);

    // save the first 6 bytes into originalBytes (buffer)
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hookedAddress, originalBytes, 6, NULL);

    // overwrite the first 6 bytes with a jump to myFunc
    myFuncAddress = fnMap[funcName];

    // create a patch "push <addr>, retn"
    // The push instruction pushes a 32bit value on the stack, and the retn instruction pops a 32bit address off the stack into the Instruction Pointer
    // meaning, when we push a function and return --> the ip will go straight to our function
    memcpy_s(patch, 1, "\x68", 1); // 0x68 opcode for push
    memcpy_s(patch + 1, 4, &myFuncAddress, 4);
    memcpy_s(patch + 5, 1, "\xC3", 1); // opcode for retn

    // write patch to the hookedAddress --> the Hooked function
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, patch, 6, NULL);
}

int main() {

    fnMap["CreateFileAHook"] = &CreateFileAHook;

    // call original
    HANDLE hFile = CreateFileA("evil.cpp",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    if (!(hFile == INVALID_HANDLE_VALUE))
        printf("Could not open file\n");
    else
        printf("Successfully opened file\n");
       
    // install hook
    SetInlineHook("CreateFileA", "CreateFileAHook");

    // call after install hook
    hFile = CreateFileA("evil.cpp",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    if (!(hFile == INVALID_HANDLE_VALUE))
        printf("Could not open file\n");
    else
        printf("Successfully opened file\n");
}
