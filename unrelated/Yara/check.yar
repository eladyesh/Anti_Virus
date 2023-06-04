import "cuckoo"
import "pe"

rule evil_doer
{
   condition:
       cuckoo.network.host(/142\.250\.186\.68/)
       or cuckoo.registry.key_access(/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/)
       or cuckoo.filesystem.file_access(/autoexec\.bat/)
}

// Rule to detect imports from KERNEL32.dll
rule kernel32_import
{
    meta:
        dll="KERNEL32"
    // strings:
    //      $i0 = "KERNEL32.DLL"
    condition:
        pe.imports("KERNEL32.DLL") 
        
}

// Rule to detect imports from ADVAPI32.dll
rule advapi32_import
{
    meta:
        dll="ADVAPI32"
    // strings:
    //      $i0 = "ADVAPI32.DLL"
    condition:
        pe.imports("ADVAPI32.DLL") 
        
}

// Rule to detect imports from WS2_32.dll
rule Ws2_32_import
{
    meta:
        dll="Ws2_32"
    // strings:
    //      $i0 = "WS2_32.DLL"
    condition:
        pe.imports("WS2_32.DLL") 
        
}

// Rule to detect imports from USER32.dll
rule USER32_import
{
    meta:
        dll="USER32"
    // strings:
    //      $i0 = "USER32.DLL"
    condition:
        pe.imports("USER32.DLL") 
        
}

// Rule to detect process enumeration related functions
rule process_enumeration
{
    strings:
        $create_snap_shot = "CreateToolhelp32Snapshot"
        $process_first = "Process32First"
        $process_next = "Process32Next"
    condition:
        // Check if any of the process enumeration functions are present
        any of ($*)
}

// Rule to detect API address search related functions
rule api_address_search
{
    strings:
        $load_library = "LoadLibrary"
        $get_proc_address = "GetProcAddress"
    condition:
        // Check if any of the API address search functions are present
        any of ($*)
}

// Rule to detect DLL operation related functions
rule dll_operations
{
    strings:
        $get_module_handle = "GetModuleHandle"
        $load_library = "LoadLibrary"
        $get_proc_address = "GetProcAddress"
    condition:
        // Check if any of the DLL operation functions are present
        any of ($*)
}

// Rule to detect keyboard hooking related functions
rule keyboard_hooking
{
    strings:
        $set_windows_hook_ex = "SetWindowsHookEx"
        $get_message = "GetMessage"
        $call_next_hook_ex = "CallNextHookEx"
        $set_file_pointer = "SetFilePointer"
        $get_key_state = "GetKeyboardState"
    condition:
        // Check if any of the keyboard hooking functions are present
        any of ($*)
}

// Rule to detect clipboard exfiltration related functions
rule clipboard_exfiltration
{
    strings:
        $open_clipboard = "OpenClipboard"
        $get_clipbaord_data = "GetClipboardData"
        $close_clip_board = "CloseClipboard"
    condition:
        // Check if any of the clipboard exfiltration functions are present
        any of ($*)
}

rule registry_operations
{
    strings:
        $anti_defneder_key = "SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $open_registry_key = "RegOpenKeyExA"
        $set_registry_value = "RegSetValueExA"
        $create_registry_key = "RegCreateKeyExA"
        $get_registry_value = "RegGetValueA"
    condition:
        // Rule to detect registry operation related functions
        any of ($*)
}

// Rule to detect socket operation related functions
rule socket_operations
{
    strings:
        $socket_open = "socket"
        $socket_connect = "connect" 
        $socket_send = "send" 
        $socket_receive = "recv"
    condition:
        // Check if any of the socket operation functions are present and if the occurrence of socket_connect is at least 2
        any of ($*) and #socket_connect >= 2 // # is for number of occurrences
}

// Rule to detect file operation related functions
rule file_operations
{
    strings:
        $create_file = "CreateFileA"
        $delete_file = "DeleteFileA"
        $write_file_ex = "WriteFileEx"
        $write_file = "WriteFile"
    condition:
        // Check if any of the file operation functions are present
        any of ($*)
}

// Rule to detect injection operation related functions
rule injection_operations 
{
    strings:
        $virtual_alloc = "VirtualAlloc"
        $virtual_alloc_ex = "VirtualAllocEx"
        $write_process_memory = "WriteProcessMemory"
        $create_thread = "CreateThread"
        $open_process = "OpenProcess"
        $create_remote_thread = "CreateRemoteThread" 
        $close_handle = "CloseHandle"
    condition:
        // Check if any of the injection operation functions are present and if the index of virtual_alloc is less than the index of write_process_memory
        any of ($*) and @virtual_alloc < @write_process_memory // @ is for index
}
