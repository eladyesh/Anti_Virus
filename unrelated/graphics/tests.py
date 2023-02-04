import pydevd
import ctypes
import subprocess


def create_file_hook(file_name, desired_access, share_mode, security_attributes, creation_disposition,
                     flags_and_attributes, template_file):
    print("CreateFileA was called with the following parameters:")
    print(f"  File name: {file_name.decode()}")
    print(f"  Desired access: {desired_access}")
    print(f"  Share mode: {share_mode}")
    print(f"  Security attributes: {security_attributes}")
    print(f"  Creation disposition: {creation_disposition}")
    print(f"  Flags and attributes: {flags_and_attributes}")
    print(f"  Template file: {template_file}")


def main():
    # Start the debugger
    pydevd.settrace('192.168.188.249', port=55555, stdoutToServer=True, stderrToServer=True)

    # Load the winapi function from kernel32.dll
    CreateFileA = ctypes.windll.kernel32.CreateFileA

    # Define the function signature for CreateFileA
    CreateFileA.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                            ctypes.c_uint32, ctypes.c_void_p]
    CreateFileA.restype = ctypes.c_void_p

    # Register the hook function
    hook = ctypes.WINFUNCTYPE(None, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                              ctypes.c_uint32, ctypes.c_void_p)(create_file_hook)
    ctypes.windll.kernel32.SetWindowsHookExA(ctypes.c_int(0), hook, ctypes.windll.kernel32[0], 0)

    # Run the virus.exe process
    subprocess.run(["virus.exe"])


if __name__ == "__main__":
    main()
