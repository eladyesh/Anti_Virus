#include <windows.h>
#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <vector>
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
  [in, optional] HANDLE hTemplateFile);

  LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
  );
*/

char originalBytes[6];
std::map<const char*, void*> fnMap;
std::map<std::string, int> fnCounter;
std::vector<std::string> suspicious_functions = { "CreateFileAHook", "VirtualAlloc"};
//std::map<FARPROC, char[6]> hook_bytes;
FARPROC hookedAddress;
void SetInlineHook(LPCSTR lpProcName, const char* funcName);

// we will jump to after the hook has been installed
void __stdcall CreateFileAHook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {


    std::cout << "\n----------intercepted call to CreateFileA----------\n";

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


    ++fnCounter[suspicious_functions[0]];
    //LOG("The number of times user is trying to Create A file is ", fnCounter[suspicious_functions[0]])

    std::cout << "\n----------Done intercepting call to CreateFileA----------\n\n";

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 6, NULL);
    CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return SetInlineHook("CreateFileA", "CreateFileAHook");
}
void __stdcall VirtualAllocHook(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD flProtect)
{
    std::cout << "\n----------intercepted call to VirtualAlloc----------\n";
    std::cout << lpAddress << std::endl;
    std::cout << "\n----------Done intercepting call to VirtualAlloc----------\n\n";

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookedAddress, originalBytes, 6, NULL);
    VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    return SetInlineHook("VirtualAlloc", "VirtualAllocHook");
}

// hooking logic
void SetInlineHook(LPCSTR lpProcName, const char* funcName) {
    HINSTANCE hLib;
    VOID* myFuncAddress;
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
    fnMap["VirtualAllocHook"] = &VirtualAllocHook;
    for (size_t i = 0; i < sizeof(suspicious_functions) / sizeof(suspicious_functions[0]); i++)
    {
        fnCounter[suspicious_functions[i]] = 0;
    }

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

    LPVOID address = VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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

    address = VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    hFile = CreateFileA("evil.txt",                // name of the write
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