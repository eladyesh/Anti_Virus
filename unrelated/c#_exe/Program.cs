using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;

namespace regular_exe
{
    internal class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
             [MarshalAs(UnmanagedType.LPStr)] string filename,
             [MarshalAs(UnmanagedType.U4)] FileAccess access,
             [MarshalAs(UnmanagedType.U4)] FileShare share,
             IntPtr securityAttributes,
             [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
             [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
             IntPtr templateFile);



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
            IntPtr a = CreateFileA("hello.txt", FileAccess.Write, FileShare.None, IntPtr.Zero, FileMode.CreateNew, FileAttributes.Normal, IntPtr.Zero);

            //uint dwHandle = (uint)CreateThread((IntPtr)0, (uint)4096, (IntPtr)null, (IntPtr)null, (uint)0, (IntPtr)null);
            //if (dwHandle == 0) throw new Exception("Unable to create thread!");
            DeleteFileA("what_is_up.txt");
        }

    }
}
