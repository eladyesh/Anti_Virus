using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace regular_exe
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CreateFileA([MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll")]
        static extern void Sleep(int dwMilliseconds);
        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeleteFileA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        static void Main(string[] args)
        {
            Sleep(2000);
            //int a = CreateFileA("hello.txt", 0, 0, (IntPtr)null, 0, 0, (IntPtr)null);

            uint dwHandle = (uint)CreateThread((IntPtr)0, (uint)4096, (IntPtr)null, (IntPtr)null, (uint)0, (IntPtr)null);
            uint dwHandle1 = (uint)CreateThread((IntPtr)0, (uint)0, (IntPtr)null, (IntPtr)null, (uint)0, (IntPtr)null);
            uint dwHandle2 = (uint)CreateThread((IntPtr)0, (uint)0, (IntPtr)null, (IntPtr)null, (uint)0, (IntPtr)null);
            if (dwHandle == 0) throw new Exception("Unable to create thread!");
            DeleteFileA("hello.txt");
            Console.WriteLine("got here");
        }

    }
}
