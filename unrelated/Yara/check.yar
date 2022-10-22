import "cuckoo"
import "pe"

rule evil_doer
{
   condition:
       cuckoo.network.host(/142\.250\.186\.68/)
       or cuckoo.registry.key_access(/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/)
       or cuckoo.filesystem.file_access(/autoexec\.bat/)
}

rule kernel32_import
{
    meta:
        dll="KERNEL32"
    // strings:
    //      $i0 = "KERNEL32.DLL"
    condition:
        pe.imports("KERNEL32.DLL") 
        
}

rule advapi32_import
{
    meta:
        dll="ADVAPI32"
    // strings:
    //      $i0 = "ADVAPI32.DLL"
    condition:
        pe.imports("ADVAPI32.DLL") 
        
}

rule Ws2_32_import
{
    meta:
        dll="Ws2_32"
    // strings:
    //      $i0 = "WS2_32.DLL"
    condition:
        pe.imports("WS2_32.DLL") 
        
}

rule USER32_import
{
    meta:
        dll="USER32"
    // strings:
    //      $i0 = "USER32.DLL"
    condition:
        pe.imports("USER32.DLL") 
        
}

rule process_enumeration
{
    strings:
        $create_snap_shot = "CreateToolhelp32Snapshot"
        $process_first = "Process32First"
        $process_next = "Process32Next"
    condition:
        any of ($*)
}

rule api_address_search
{
    strings:
        $load_library = "LoadLibrary"
        $get_proc_address = "GetProcAddress"
    condition:
        any of ($*)
}

rule dll_operations
{
    strings:
        $get_module_handle = "GetModuleHandle"
        $load_library = "LoadLibrary"
        $get_proc_address = "GetProcAddress"
    condition:
        any of ($*)
}


rule api_hooking
{
    strings:
        $set_windows_hook_ex = "SetWindowsHookEx"
        $get_message = "GetMessage"
        $call_next_hook_ex = "CallNextHookEx"
    condition:
        any of ($*)
}

rule clipboard_exfiltration
{
    strings:
        $open_clipboard = "OpenClipboard"
        $get_clipbaord_data = "GetClipboardData"
        $close_clip_board = "CloseClipboard"
    condition:
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
        any of ($*)
}

rule socket_operations
{
    strings:
        $socket_open = "socket"
        $socket_connect = "connect" 
        $socket_send = "send" 
        $socket_receive = "recv"
    condition:
        any of ($*)
}

rule file_operations
{
    strings:
        $create_file = "CreateFileA"
        $delete_file = "DeleteFileA"
        $write_file_ex = "WriteFileEx"
        $write_file = "WriteFile"
    condition:
        any of ($*)
}

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
        any of ($*)
}
