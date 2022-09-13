#include "pch.h"

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

*/

//char originalBytes[6];
std::map<const char*, void*> fnMap;
std::map<std::string, int> fnCounter;
std::vector<const char*> suspicious_functions = { "CreateFileA", "VirtualAlloc", "CreateThread", "RegOpenKeyExA", "RegSetValueExA", "RegCreateKeyExA"};
std::vector<FARPROC> addresses(6);
std::vector<char[6]> original(6);
HANDLE file = NULL;
std::ofstream myfile;
std::map<const char*, int> function_index;
void SetInlineHook(LPCSTR lpProcName, const char* library, const char* funcName, int index);
//PROCESS_INFORMATION pi;
HANDLE hFile;

template<typename T>
void LOG(const char* message, T parameter) {
    myfile << message << parameter << "\n";
    //WriteFile(hFile, message, strlen(message), NULL, nullptr);
    //WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
    //WriteFile(hFile,(LPCVOID)parameter, sizeof((LPCVOID)parameter), NULL, nullptr);
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
        LOG("The number of times user is trying to Create A file is ", fnCounter[suspicious_functions[index]]);
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
        LOG("The number of times user is trying to  file is ", fnCounter[suspicious_functions[index]]);
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
        LOG("The number of times user is trying to  file is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to CreateThread----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        return SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", index);
    }
    static void __stdcall RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
        
        LOG("\n----------intercepted call to RegOpenKeyExA----------\n\n", "");
        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002)))
            LOG("The key opened is ", "HKEY_LOCAL_MACHINE");

        LOG("The name of the registry subkey to be opened is ", lpSubKey);
        LOG("The option to apply when opening the key is ", ulOptions);
        LOG("A mask that specifies the desired access rights to the key to be opened is ", samDesired);

        int index = function_index["RegOpenKeyExA"];
        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to  file is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to RegOpenKeyExA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        return SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);

    }
    static void __stdcall RegSetValueExAHook(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
        
        LOG("\n----------intercepted call to RegSetValueExA----------\n\n", "");
        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002)))
            LOG("The key opened is ", "HKEY_LOCAL_MACHINE");

        //std::cout << lpValueName << std::endl;
        //std::cout << Reserved << std::endl;
        //std::cout << dwType << std::endl;
        //std::cout << lpData << std::endl;
        //std::cout << cbData << std::endl;

        int index = function_index["RegSetValueExA"];
        ++fnCounter[suspicious_functions[index]];
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
        return SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);
    }
    static void __stdcall RegCreateKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
        std::cout << "Got to CreateKey" << std::endl;

        int index = function_index["RegCreateKeyExA"];
        ++fnCounter[suspicious_functions[index]];
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
        return SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);
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

    fnMap["CreateFileAHook"] = &HOOKING::CreateFileAHook;
    fnMap["VirtualAllocHook"] = &HOOKING::VirtualAllocHook;
    fnMap["CreateThreadHook"] = &HOOKING::CreateThreadHook;
    fnMap["RegOpenKeyExAHook"] = &HOOKING::RegOpenKeyExAHook;
    fnMap["RegSetValueExAHook"] = &HOOKING::RegSetValueExAHook;
    fnMap["RegCreateKeyExAHook"] = &HOOKING::RegCreateKeyExAHook;
    for (int i = 0; i < suspicious_functions.size(); i++)
    {
        fnCounter[suspicious_functions[i]] = 0;
        function_index[suspicious_functions[i]] = i;
    }

    myfile.open("LOG.txt");
    //hFile = CreateFile(L"LOG.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    //// Open a handle to the file                 
    //if (hFile == INVALID_HANDLE_VALUE)
    //{
    //    // Failed to open/create file
    //    return 2;
    //}
    //STARTUPINFO si;
    //ZeroMemory(&si, sizeof(si));
    //si.cb = sizeof(si);
    //ZeroMemory(&pi, sizeof(pi));
    //BOOL bSuccess = CreateProcess(L"virus.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    //if (bSuccess) {
    //    DWORD dwPid = GetProcessId(pi.hProcess);
    //    file = OpenProcess(MAXIMUM_ALLOWED | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid);
    //}

    SetInlineHook("CreateFileA", "kernel32.dll", "CreateFileAHook", function_index["CreateFileA"]);
    SetInlineHook("VirtualAlloc", "kernel32.dll",  "VirtualAllocHook", function_index["VirtualAlloc"]);
    SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", function_index["CreateThread"]);
    SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);
    SetInlineHook("RegSetValueExA", "advapi32.dll", "RegSetValueExAHook", function_index["RegSetValueExA"]);
    SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);

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

    address = VirtualAlloc(NULL, 11, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);
    CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);

    HKEY key;
    HKEY new_key;
    DWORD disable = 1;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
    RegSetValueExA(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
    //ResumeThread(pi.hThread);
    //CloseHandle(pi.hThread);
    //CloseHandle(file);
    myfile.close();
    return 0;
}