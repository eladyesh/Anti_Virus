rule process_enumeration
{
    strings:
        $create_snap_shot = "CreateToolhelp32Snapshot" nocase wide ascii
        $process_first = "Process32First" nocase wide ascii
        $process_next = "Process32Next" nocase wide ascii
    condition:
        any of ($*)
}

rule api_address_search
{
    strings:
        $load_library = "LoadLibrary" nocase wide ascii
        $get_proc_address = "GetProcAddress" nocase wide ascii
    condition:
        any of ($*)
}

rule dll_operations
{
    strings:
        $get_module_handle = "GetModuleHandle" nocase wide ascii
        $load_library = "LoadLibrary" nocase wide ascii
        $get_proc_address = "GetProcAddress" nocase wide ascii
    condition:
        any of ($*)
}


rule api_hooking
{
    strings:
        $set_windows_hook_ex = "SetWindowsHookEx" nocase wide ascii
        $get_message = "GetMessage" nocase wide ascii
        $call_next_hook_ex = "CallNextHookEx" nocase wide ascii
    condition:
        any of ($*)
}

rule clipboard_exfiltration
{
    strings:
        $open_clipboard = "OpenClipboard" nocase wide ascii
        $get_clipbaord_data = "GetClipboardData" nocase wide ascii
        $close_clip_board = "CloseClipboard" nocase wide ascii
    condition:
        any of ($*)
}

rule registry_operations
{
    strings:
        $open_registry_key = "RegOpenKeyExA" nocase wide ascii
        $set_registry_value = "RegSetValueExA" nocase wide ascii
        $create_registry_key = "RegCreateKeyExA" nocase wide ascii
        $get_registry_value = "RegGetValueA" nocase wide ascii
    condition:
        any of ($*)
}

rule socket_operations
{
    strings:
        $socket_open = "socket" nocase wide ascii
        $socket_connect = "connect" nocase wide ascii
        $socket_send = "send" nocase wide ascii
        $socket_receive = "recv" nocase wide ascii
    condition:
        any of ($*)
}

rule file_operations
{
    strings:
        $create_file = "CreateFileA" nocase wide ascii
        $delete_file = "DeleteFileA" nocase wide ascii
        $write_file_ex = "WriteFileEx" nocase wide ascii
        $write_file = "WriteFile" nocase wide ascii
    condition:
        any of ($*)
}

rule injection_operations 
{
    strings:
        $virtual_alloc = "VirtualAlloc" nocase wide ascii
        $virtual_alloc_ex = "VirtualAllocEx" nocase wide ascii
        $write_process_memory = "WriteProcessMemory" nocase wide ascii
        $create_thread = "CreateThread" nocase wide ascii
        $open_process = "OpenProcess" nocase wide ascii
        $create_remote_thread = "CreateRemoteThread" nocase wide ascii
        $close_handle = "CloseHandle"
    condition:
        any of ($*)
}
