/* In order for c# to work, you have to turn off the VirtualAlloc, CreateThread, And OpenProcess Hooks */

#include "pch.h"
#include "cpu.h"
#include <Windows.h>
#include <thread>
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
#include <tlhelp32.h>
#include <cmath>
#include <limits>
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

  BOOL DeleteFileA(
  [in] LPCSTR lpFileName
   );

   BOOL WriteFileEx(
  [in]           HANDLE                          hFile,
  [in, optional] LPCVOID                         lpBuffer,
  [in]           DWORD                           nNumberOfBytesToWrite,
  [in, out]      LPOVERLAPPED                    lpOverlapped,
  [in]           LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

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

    LSTATUS RegGetValueA(
   [in]                HKEY    hkey,
   [in, optional]      LPCSTR  lpSubKey,
   [in, optional]      LPCSTR  lpValue,
   [in, optional]      DWORD   dwFlags,
   [out, optional]     LPDWORD pdwType,
   [out, optional]     PVOID   pvData,
   [in, out, optional] LPDWORD pcbData
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

    int WSAAPI send(
    [in] SOCKET     s,
    [in] const char *buf,
    [in] int        len,
    [in] int        flags
    );

    int recv(
    [in]  SOCKET s,
    [out] char   *buf,
    [in]  int    len,
    [in]  int    flags
    );

    BOOL CloseHandle(
        [in] HANDLE hObject
        );

    BOOL WriteFile(
        [in]                HANDLE       hFile,
        [in]                LPCVOID      lpBuffer,
        [in]                DWORD        nNumberOfBytesToWrite,
        [out, optional]     LPDWORD      lpNumberOfBytesWritten,
        [in, out, optional] LPOVERLAPPED lpOverlapped
    );
    // std::vector<LPVOID> winapi_functions = { CreateFileA, DeleteFileA, WriteFileEx, WriteFile, VirtualAlloc, CreateThread, OpenProcess, VirtualAllocEx, CreateRemoteThread, CloseHandle, RegOpenKeyExA, RegSetValueExA, RegCreateKeyExA, RegGetValueA, socket, connect, send, recv };
*/

// Intializing maps and lists of suspicious function
std::map<const char*, void*> fnMap;
std::map<std::string, int> fnCounter;
std::vector<const char*> suspicious_functions = { "CreateFileA", "DeleteFileA", "WriteFileEx", "WriteFile", "VirtualAlloc", "CreateThread", "OpenProcess", "VirtualAllocEx", "CreateRemoteThread", "CloseHandle", "RegOpenKeyExA", "RegSetValueExA", "RegCreateKeyExA", "RegGetValueA", "socket", "connect", "send", "recv", "SetWindowsHookExA", "GetKeyboardState", "SetFilePointer"};
std::vector<FARPROC> addresses(21);
std::vector<char[6]> original(21);
std::map<HANDLE, int> handle_counter;
std::map<const char*, int> function_index;

// vectors for the parameters from the parameters file
std::vector<std::string> files(1);
std::vector<std::string> ports(1);
std::vector<std::string> keys(1);

void SetInlineHook(LPCSTR lpProcName, const char* library, const char* funcName, int index);
void FreeHook(int index);
HANDLE hFile;
int writeFileIndex = 0;

// cpu
double cpuPermitted = 0.0;
double maxCpu = 0;

// port scanning variables
const char* remote_ip; std::string injected_process = "";
int connect_count = 0, run_once = 1; bool portScanner = false;

// keboard hook counter
int keyboard_hook = 0;
int show_identified = 0;


namespace FindProcess {
    DWORD FindProcessId(const std::wstring& processName)
    {
        PROCESSENTRY32 processInfo;
        processInfo.dwSize = sizeof(processInfo);

        HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (processesSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        Process32First(processesSnapshot, &processInfo);
        if (!processName.compare(processInfo.szExeFile))
        {
            //CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }

        while (Process32Next(processesSnapshot, &processInfo))
        {
            if (!processName.compare(processInfo.szExeFile))
            {
                //CloseHandle(processesSnapshot);
                return processInfo.th32ProcessID;
            }
        }

        //CloseHandle(processesSnapshot);
        return 0;
    }
    const std::wstring FindProcessName(DWORD id)
    {
        PROCESSENTRY32 processInfo;
        processInfo.dwSize = sizeof(processInfo);

        HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (processesSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        Process32First(processesSnapshot, &processInfo);
        if (processInfo.th32ProcessID == id)
        {
            //CloseHandle(processesSnapshot);
            return processInfo.szExeFile;
        }

        while (Process32Next(processesSnapshot, &processInfo))
        {
            if (processInfo.th32ProcessID == id)
            {
                //CloseHandle(processesSnapshot);
                return processInfo.szExeFile;
            }
        }

        //CloseHandle(processesSnapshot);
        return 0;
    }
}

namespace StringAnalyzer {
    int CountString(std::string s, char a) {
        int count = 0;
        for (size_t i = 0; i < s.length(); i++)
        {
            if (s[i] == a) count++;
        }
        return count;
    }
    bool CompareStrings(std::string s1, std::string s2) {

        for (size_t i = 0; i < s1.length(); i++)
        {
            if ((char)s1[i] != (char)s2[i]) return false;
        }
        return true;
    }
}

namespace CheckContain {
    bool contains(std::vector<std::string> vec, std::string elem, bool Compare)
    {
        bool result = false;
        if (Compare) {
            for (std::string x : vec) {
                if (StringAnalyzer::CompareStrings(elem, x)) return true;
            }
        }
        else {
            for (size_t i = 1; i < vec.size(); i++)
            {
                if (elem.find(vec[i]) != std::string::npos)
                {
                    result = true;
                    break;
                }
            }
        }
        return result;
    }
    bool ContainsHandle(HANDLE h) {
        if (handle_counter.find(h) == handle_counter.end())
            return false;
        return true;
    }

}

// clock
std::chrono::steady_clock::time_point begin;

template<typename T>
void LOG(const char* message, T parameter) {

    FreeHook(writeFileIndex);
    WriteFile(hFile, message, strlen(message), NULL, nullptr);
    //WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
    ostringstream oss;
    ostringstream oss2;
    oss << parameter << ends;

    // cpu
    std::string param = oss.str().c_str();
    if (param == std::string("-nan(ind)")) {
        WriteFile(hFile, "0", strlen("0"), NULL, nullptr);
    }
    else {
        WriteFile(hFile, oss.str().c_str(), strlen(oss.str().c_str()), NULL, nullptr);
    }
    WriteFile(hFile, "\n", strlen("\n"), NULL, nullptr);
    SetInlineHook("WriteFile", "kernel32.dll", "WriteFileHook", writeFileIndex);

}


struct REGISTRY_HOOKING {
    static void __stdcall RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {

        bool run_key = false;
        LOG("\n----------intercepted call to RegOpenKeyExA----------\n\n", "");
        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002))) {
            LOG("The key opened is ", "HKEY_LOCAL_MACHINE");
        }

        if (hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000001))) {
            LOG("The key opened is ", "HKEY_CURRENT_USER");
        }


        LOG("The name of the registry subkey to be opened is ", lpSubKey);
        LOG("The option to apply when opening the key is ", ulOptions);

        if (samDesired == 0xF003F)
            LOG("A mask that specifies the desired access rights to the key to be opened is ", "KEY_ALL_ACCESS");

        if (CheckContain::contains(keys, std::string(lpSubKey), true))
            LOG("EXE is trying to access a suspicious registry key!", "");

        int index = function_index["RegOpenKeyExA"];
        ++fnCounter[suspicious_functions[index]];

        //if ((hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000001)) || hKey == ((HKEY)(ULONG_PTR)((LONG)0x80000002))) &&
        //    lpSubKey == (LPCSTR)"Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
        //    LOG("\nExe probably trying to execute a file after every rebot through a Run key!!", "");
        //

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to open a registry key is ", fnCounter[suspicious_functions[index]]);
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to set a registry key is ", fnCounter[suspicious_functions[index]]);
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to create a registry key is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to RegCreateKeyExA----------\n\n\n\n\n", "");


        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
        return SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);

    }
    static void __stdcall RegGetValueAHook(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) {

        LOG("\n----------intercepted call to RegGetValueA----------\n\n", "");
        LOG("The key opened is ", hkey);
        LOG("The name of a subkey that this function opens or creates is ", lpSubKey);
        LOG("The name of the Registry Value Name this function is trying to reach is ", lpValue);

        if (dwFlags == 0x0000ffff)
            LOG("The specified flags for this questions is ", "RRF_RT_ANY");

        int index = function_index["RegGetValueA"];
        ++fnCounter[suspicious_functions[index]];
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);

        char value[255];
        DWORD BufferSize = 8192;
        RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, (PVOID)&value, &BufferSize);

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The Registry Value Data this function was trying to get to is ", value);

        LOG("The number of times user is trying to get a registry value is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to RegGetValueA----------\n\n\n\n\n", "");

        return SetInlineHook("RegGetValueA", "advapi32.dll", "RegGetValueAHook", function_index["RegGetValueA"]);
    }
};

struct SOCKET_HOOKING {
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to create a socket is ", fnCounter[suspicious_functions[index]]);
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

        ostringstream oss;
        oss << port << ends;

        char* ip = inet_ntoa((*sin).sin_addr);
        if (run_once == 1) remote_ip = ip; run_once = 0;
        LOG("\n----------intercepted call to connect----------\n\n", "");

        if (CheckContain::contains(ports, std::string(oss.str()), true))
            LOG("EXE is trying to connect through a suspicious port!", "");

        LOG("The address socket is trying to connect to is ", ip);
        LOG("The port socket is using to connect is ", port);

        int index = function_index["connect"];
        if (run_once == 0) {
            if (fnCounter[suspicious_functions[index]] + 1 == fnCounter[suspicious_functions[function_index["socket"]]] && remote_ip == ip) {
                connect_count++;
            }
            if (connect_count >= 3) {
                portScanner = true;
                LOG("\n----------IDENTIFIED PORT SCANNING----------\n", "");
                connect_count = 0;
            }
        }
        ++fnCounter[suspicious_functions[index]];

        ostringstream oss2;
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        oss2 << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss2.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to connect to another socket is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to connect----------\n\n\n\n\n", "");


        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int r = connect(s, name, namelen);
        SetInlineHook("connect", "Ws2_32.dll", "connectHook", function_index["connect"]);
        return r;
    }
    static int __stdcall sendHook(SOCKET s, const char* buff, int len, int flags) {

        LOG("\n----------intercepted call to send----------\n\n", "");
        LOG("The buffer wanted to be send is ", std::string(buff));
        LOG("The length of the buffer is ", len);

        int index = function_index["send"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to send message via socket is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to send----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int b = send(s, buff, len, flags);
        SetInlineHook("send", "Ws2_32.dll", "sendHook", index);
        return b;
    }
    static int __stdcall recvHook(SOCKET s, char* buff, int len, int flags) {

        LOG("\n----------intercepted call to recv----------\n\n", "");

        int index = function_index["recv"];
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int b = recv(s, buff, len, flags);

        LOG("The buffer socket recieved is \n\n", buff);
        LOG("\n", "\n");

        size_t length = strlen(buff);
        LOG("The length of the buffer is ", length);

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        ++fnCounter[suspicious_functions[index]];
        LOG("The number of times user is trying to receive a buffer is ", fnCounter[suspicious_functions[index]]);

        LOG("\n----------Done intercepting call to recv----------\n\n\n\n\n", "");

        SetInlineHook("recv", "Ws2_32.dll", "recvHook", index);
        return b;
    }
};

struct FILE_HOOKING {
    static void __stdcall CreateFileAHook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

        LOG("\n----------intercepted call to CreateFileA----------\n\n", "");

        if (CheckContain::contains(files, std::string(lpFileName), false))
            LOG("EXE file is tring to reach a suspicious folder!", "");

        LOG("The name of the file or device to be created or opened is ", lpFileName);
        LOG("The requested access to the file or device is ", dwDesiredAccess);
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to create a file is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to CreateFileA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        return SetInlineHook("CreateFileA", "kernel32.dll", "CreateFileAHook", index);
    }
    static int __stdcall DeleteFileAHook(LPCSTR lpFileName) {

        LOG("\n----------intercepted call to DeleteFileA----------\n\n", "");
        LOG("The path to the file that is to be deleted is ", lpFileName);

        int index = function_index["DeleteFileA"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        LOG("The number of times user is trying to delete a file is ", fnCounter[suspicious_functions[index]]);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);
        LOG("\n----------Done intercepting call to DeleteFileA----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int success = DeleteFileA(lpFileName);
        SetInlineHook("DeleteFileA", "kernel32.dll", "DeleteFileAHook", index);
        return success;
    }
    static int __stdcall WriteFileExHook(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {

        LOG("\n----------intercepted call to WriteFileEx----------\n\n", "");
        LOG("The handle to this file is ", hFile);
        LOG("The buffer being written to the file is ", (LPCSTR)lpBuffer);
        LOG("The size of the buffer is ", nNumberOfBytesToWrite);

        int index = function_index["WriteFileEx"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to write to a file is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to WriteFileEx----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int b = WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
        SetInlineHook("WriteFileEx", "kernel32.dll", "WriteFileExHook", index);
        return b;
    }
    static BOOL __stdcall WriteFileHook(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

        LOG("\n----------intercepted call to WriteFile----------\n\n", "");
        LOG("The handle to this file is ", hFile);
        LOG("The buffer being written to the file is ", (LPCSTR)lpBuffer);
        LOG("The size of the buffer is ", nNumberOfBytesToWrite);

        if (keyboard_hook >= 2) {
            if (show_identified == 0) {
                LOG("\n----------IDENTIFIED KEYBOARD LOGGING----------\n", "");
                show_identified = 1;
            }
        }

        int index = function_index["WriteFile"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);
        LOG("The number of times user is trying to write to a file is ", fnCounter[suspicious_functions[index]]);

        LOG("\n----------Done intercepting call to WriteFile----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        BOOL success = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
        SetInlineHook("WriteFile", "kernel32.dll", "WriteFileHook", index);
        return success;
    }
};

struct INJECT_HOOKING {
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to allocate memory is ", fnCounter[suspicious_functions[index]]);
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

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);
        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to create a thread is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to CreateThread----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        return SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", index);
    }
    static HANDLE __stdcall OpenProcessHook(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {


        const std::wstring name1 = FindProcess::FindProcessName(dwProcessId);
        std::string str1(name1.begin(), name1.end());
        if (str1 == std::string("VIRUS.EXE") || str1 == std::string("virus.exe")) return NULL;

        LOG("\n----------intercepted call to OpenProcess----------\n\n", "");

        if (dwDesiredAccess == ((0x000F0000L) | (0x00100000L) | (0xFFFF)))
            LOG("The permissions to this process is ", "PROCESS_ALL_ACCESS");

        LOG("processes created by this process will inherit the handle - ", bInheritHandle);
        LOG("The process id is ", dwProcessId);

        const std::wstring name = FindProcess::FindProcessName(dwProcessId);
        std::string str(name.begin(), name.end());
        injected_process = str;
        LOG("Function is trying to open process ", str);

        int index = function_index["OpenProcess"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to open a process is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to OpenProcess----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        HANDLE h = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        handle_counter[h] = 0;
        SetInlineHook("OpenProcess", "kernel32.dll", "OpenProcessHook", index);
        return h;
    }
    static LPVOID __stdcall VirtualAllocExHook(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        LOG("\n----------intercepted call to VirtualAllocEx----------\n\n", "");

        LOG("The handle to the process is ", hProcess);
        LOG("The pointer that specifies a desired starting address for the region of pages that function wants to allocate is ", lpAddress);
        LOG("Size of allocation is ", dwSize);

        if (flAllocationType == 0x00001000 | 0x00002000)
            LOG("The type of allocation is memory committing and reserving", "");

        if (flProtect == 0x40)
            LOG("The memory protection for the region of pages to be allocated is ", "PAGE_EXECUTE_READWRITE");

        if (CheckContain::ContainsHandle(hProcess)) handle_counter[hProcess] = 1;

        int index = function_index["VirtualAllocEx"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to allocate memory is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to VirtualAllocEx----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        LPVOID rb = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
        SetInlineHook("VirtualAllocEx", "kernel32.dll", " VirtualAllocExHook", index);
        return rb;
    }
    static HANDLE __stdcall CreateRemoteThreadHook(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
        LOG("\n----------intercepted call to CreateRemoteThread----------\n\n", "");

        LOG("A handle to the process in which the thread is to be created is ", hProcess);
        LOG("The initial size of the stack, in bytes is ", dwStackSize);
        LOG("A pointer to a variable to be passed to the thread function is ", lpParameter);

        if (lpThreadId == 0)
            LOG("Thread runs immediately after creation", "");

        int index = function_index["CreateRemoteThread"];
        ++fnCounter[suspicious_functions[index]];

        if (handle_counter[hProcess] == 1) {
            std::string log = "";
            log += "\n----------IDENTIFIED INJECTION into process ";
            log += injected_process;
            log += "----------\n";
            LOG(log.c_str(), "");
        }

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to create a remote thread is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to CreateRemoteThread----------\n\n\n\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        HANDLE h = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        SetInlineHook("CreateRemoteThread", "kernel32.dll", "CreateRemoteThreadHook", index);
        return h;
    }
    static int __stdcall CloseHandleHook(HANDLE hObject) {

        LOG("\n----------intercepted call to CloseHandle----------\n\n", "");
        LOG("The handle to be closed is ", hObject);

        int index = function_index["CloseHandle"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("The number of times user is trying to close a handle is ", fnCounter[suspicious_functions[index]]);
        LOG("\n----------Done intercepting call to CloseHandle----------\n\n\n\n\n", "");

        std::map<HANDLE, int>::iterator it;

        if (CheckContain::ContainsHandle(hObject)) {
            //for (size_t i = 0; i < openHandles.size(); i++)
            //{
            //    ostringstream oss2;
            //    oss2 << openHandles[i] << ends;

            //    if (std::string(oss2.str()) == std::string(oss1.str()))
            //        openHandles.erase(openHandles.begin() + i);
            //}
            it = handle_counter.find(hObject);
            handle_counter.erase(it);
        }

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        int n = CloseHandle(hObject);
        SetInlineHook("CloseHandle", "kernel32.dll", "CloseHandleHook", index);
        return n;
    }
};

struct KeyBoard_HOOKING
{
    // start with SetWindowsHookExA, and follow the code in de_bug
    static HHOOK __stdcall SetWindowsHookExAHook(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {

        LOG("\n----------intercepted call to SetWindowsHookExA----------\n\n", "");

        if (idHook == 13)
            LOG("The type of hook to be installed is ", "WH_KEYBOARD_LL");
        LOG("A pointer to the hook procedure is ", lpfn);
        LOG("A handle to the DLL containing the hook procedure pointed to by the lpfn parameter is ", hMod);
        
        if (dwThreadId == 0)
            LOG("The hook procedure is associated with all existing threads running in the same desktop as the calling thread.", "");

        int index = function_index["SetWindowsHookExA"];
        ++fnCounter[suspicious_functions[index]];

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("\n----------Done intercepting call to SetWindowsHookExA----------\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        HHOOK hHook = SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
        SetInlineHook("SetWindowsHookExA", "user32.dll", "SetWindowsHookExAHook", index);
        return hHook;
    }
    static BOOL __stdcall GetKeyboardStateHook(PBYTE lpKeyState) {

        LOG("\n----------intercepted call to GetKeyboardState----------\n\n", "");
        LOG("The 256-byte array that receives the status data for each virtual key is ", lpKeyState);
        
        int index = function_index["GetKeyboardState"];
        ++fnCounter[suspicious_functions[index]];
        keyboard_hook++;

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("\n----------Done intercepting call to GetKeyboardState----------\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        BOOL b = GetKeyboardState(lpKeyState);
        SetInlineHook("GetKeyboardState", "user32.dll", "GetKeyboardStateHook", function_index["GetKeyboardState"]);
        return b;
    }

    static DWORD __stdcall SetFilePointerHook(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {

        LOG("\n----------intercepted call to SetFilePointer----------\n\n", "");
        LOG("The handle to the file is ", hFile);
        LOG("The number of bytes to move the file pointer is ", lDistanceToMove);
        LOG("A pointer to a variable that contains the high-order 32 bits of the new file pointer is ", lpDistanceToMoveHigh);
        
        if (dwMoveMethod == 0)
            LOG("The starting point for the file pointer move is ", "FILE_BEGIN");
        if (dwMoveMethod == 1)
            LOG("The starting point for the file pointer move is ", "FILE_CURRENT");
        if (dwMoveMethod == 2)
            LOG("The starting point for the file pointer move is ", "FILE_END");

        int index = function_index["SetFilePointer"];
        ++fnCounter[suspicious_functions[index]];
        keyboard_hook++;

        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        ostringstream oss;
        oss << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << ends;
        std::string time_difference = std::string(oss.str().c_str());
        time_difference.insert(1, ".");

        LOG("Time difference since attachment of hooks in [s] is ", time_difference);

        double cpuUsage = getCurrentValue();
        if (cpuUsage == -std::nan("ind")) cpuUsage = 0;
        if (cpuUsage < cpuUsage) cpuUsage = cpuUsage;
        while (cpuUsage > 100.0) cpuUsage -= 70.0;
        if (cpuUsage > cpuPermitted) LOG("Has passed permitted cpu", "");
        LOG("The current cpu usage percantage [%] is ", cpuUsage);

        LOG("\n----------Done intercepting call to SetFilePointer----------\n\n", "");

        WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
        DWORD d = SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
        SetInlineHook("SetFilePointer", "kernel32.dll", "SetFilePointerHook", function_index["SetFilePointer"]);
        return d;

    }
};

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
void FreeHook(int index) {
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)addresses[index], original[index], 6, NULL);
}

// parse
void ParseParameters() {

    init();
    DWORD nRead;
    HANDLE htxtFile = CreateFile(L"parameters.txt", FILE_SHARE_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    std::vector<std::string> parameters(1);
    char buff[600] = { 0 };

    std::string s = "";
    if (ReadFile(htxtFile, buff, 600, &nRead, 0) == FALSE) {
        DWORD err = GetLastError();
        std::cout << "ReadFile err: " << err << std::endl;
    }

    for (char a : buff) {
        if (a != '\n' && a != '\r')
            s += a;
        else {
            parameters.push_back(s);
            s = "";
        }
    }

    for (size_t i = 0; i < parameters.size(); i++) {
        if (parameters[i].empty()) {
            parameters.erase(parameters.begin() + i);
        }
    }

    for (size_t i = 0; i < parameters.size(); i++) {
        if (isdigit(parameters[i][0])) {
            ports.push_back(parameters[i]);
        }
        else if (isalpha(parameters[i][0]) && parameters[i].length() > 30) {
            keys.push_back(parameters[i]);
        }
        else if (isalpha(parameters[i][0]) && parameters[i].length() < 30) {

            if (parameters[i][0] == 'C' && parameters[i][1] == 'P' && parameters[i][2] == 'U') {
                std::string cpU(parameters[i].substr(parameters[i].size() - 2));
                cpuPermitted = (double)std::stoi(cpU);
            }
            files.push_back(parameters[i]);
        }
    }
}

int main() {

    ParseParameters();

    fnMap["CreateFileAHook"] = (void*)&FILE_HOOKING::CreateFileAHook;
    fnMap["DeleteFileAHook"] = (void*)&FILE_HOOKING::DeleteFileAHook;
    fnMap["WriteFileExHook"] = (void*)&FILE_HOOKING::WriteFileExHook;
    fnMap["WriteFileHook"] = (void*)&FILE_HOOKING::WriteFileHook;

    fnMap["VirtualAllocHook"] = (void*)&INJECT_HOOKING::VirtualAllocHook;
    fnMap["CreateThreadHook"] = (void*)&INJECT_HOOKING::CreateThreadHook;
    fnMap["OpenProcessHook"] = (void*)&INJECT_HOOKING::OpenProcessHook;
    fnMap["VirtualAllocExHook"] = (void*)&INJECT_HOOKING::VirtualAllocExHook;
    fnMap["CreateRemoteThreadHook"] = (void*)&INJECT_HOOKING::CreateRemoteThreadHook;
    fnMap["CloseHandleHook"] = (void*)&INJECT_HOOKING::CloseHandleHook;

    fnMap["RegOpenKeyExAHook"] = (void*)&REGISTRY_HOOKING::RegOpenKeyExAHook;
    fnMap["RegSetValueExAHook"] = (void*)&REGISTRY_HOOKING::RegSetValueExAHook;
    fnMap["RegCreateKeyExAHook"] = (void*)&REGISTRY_HOOKING::RegCreateKeyExAHook;
    fnMap["RegGetValueAHook"] = (void*)&REGISTRY_HOOKING::RegGetValueAHook;

    fnMap["socketHook"] = (void*)&SOCKET_HOOKING::socketHook;
    fnMap["connectHook"] = (void*)&SOCKET_HOOKING::connectHook;
    fnMap["sendHook"] = (void*)&SOCKET_HOOKING::sendHook;
    fnMap["recvHook"] = (void*)&SOCKET_HOOKING::recvHook;

    fnMap["SetWindowsHookExAHook"] = (void*)&KeyBoard_HOOKING::SetWindowsHookExAHook;
    fnMap["GetKeyboardStateHook"] = (void*)&KeyBoard_HOOKING::GetKeyboardStateHook;
    fnMap["SetFilePointerHook"] = (void*)&KeyBoard_HOOKING::SetFilePointerHook;

    for (int i = 0; i < suspicious_functions.size(); i++)
    {
        fnCounter[suspicious_functions[i]] = 0;
        function_index[suspicious_functions[i]] = i;
    }

    writeFileIndex = function_index["WriteFile"];

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

    init();

    SetInlineHook("CreateFileA", "kernel32.dll", "CreateFileAHook", function_index["CreateFileA"]);
    SetInlineHook("DeleteFileA", "kernel32.dll", "DeleteFileAHook", function_index["DeleteFileA"]);
    SetInlineHook("WriteFileEx", "kernel32.dll", "WriteFileExHook", function_index["WriteFileEx"]);
    SetInlineHook("WriteFile", "kernel32.dll", "WriteFileHook", function_index["WriteFile"]);

    // SetInlineHook("VirtualAlloc", "kernel32.dll", "VirtualAllocHook", function_index["VirtualAlloc"]);
    // SetInlineHook("CreateThread", "kernel32.dll", "CreateThreadHook", function_index["CreateThread"]);
    SetInlineHook("OpenProcess", "kernel32.dll", "OpenProcessHook", function_index["OpenProcess"]);
    SetInlineHook("VirtualAllocEx", "kernel32.dll", "VirtualAllocExHook", function_index["VirtualAllocEx"]);
    SetInlineHook("CreateRemoteThread", "kernel32.dll", "CreateRemoteThreadHook", function_index["CreateRemoteThread"]);
    // SetInlineHook("CloseHandle", "kernel32.dll", "CloseHandleHook", function_index["CloseHandle"]);

    SetInlineHook("RegOpenKeyExA", "advapi32.dll", "RegOpenKeyExAHook", function_index["RegOpenKeyExA"]);
    SetInlineHook("RegSetValueExA", "advapi32.dll", "RegSetValueExAHook", function_index["RegSetValueExA"]);
    SetInlineHook("RegCreateKeyExA", "advapi32.dll", "RegCreateKeyExAHook", function_index["RegCreateKeyExA"]);
    SetInlineHook("RegGetValueA", "advapi32.dll", "RegGetValueAHook", function_index["RegGetValueA"]);

    SetInlineHook("socket", "Ws2_32.dll", "socketHook", function_index["socket"]);
    SetInlineHook("connect", "Ws2_32.dll", "connectHook", function_index["connect"]);
    SetInlineHook("send", "Ws2_32.dll", "sendHook", function_index["send"]);
    SetInlineHook("recv", "Ws2_32.dll", "recvHook", function_index["recv"]);

    SetInlineHook("SetWindowsHookExA", "user32.dll", "SetWindowsHookExAHook", function_index["SetWindowsHookExA"]);
    SetInlineHook("GetKeyboardState", "user32.dll", "GetKeyboardStateHook", function_index["GetKeyboardState"]);
    SetInlineHook("SetFilePointer", "kernel32.dll", "SetFilePointerHook", function_index["SetFilePointer"]);

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


// extern function
extern "C" void startMain() {
    main();
}
