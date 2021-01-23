using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Memdumper {
    class Program {

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            int dwDesitedAccess,
            bool bInheritHandle,
            int dwProcessID);

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            IntPtr dwSize,
            ref int lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        const int PROCESS_ALL_ACCESS = (0x1F0FFF);
        const int MEM_COMMIT = (0x00001000);
        const int MEM_FREE = (0x00010000);
        const int MEM_PRIVATE = (0x00020000);
        const int MEM_IMAGE = (0x01000000);
        const int MEM_MAPPED = (0x00040000);
        const int PAGE_NOACCESS = (0x01);

        static void Main(string[] args) {
            List<string> dump = new List<string>();
            int pid = Process.GetProcessesByName("explorer").FirstOrDefault().Id;
            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
            int memInfoSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            byte first = 0, second = 0;
            bool uFlag = true, isUnicode = false;

            Console.Title = "PcaClient viewer by @italianncheater";
            Console.ForegroundColor = ConsoleColor.White;

            for (IntPtr p = IntPtr.Zero;
                VirtualQueryEx(hProc, p, out memInfo,
                (uint)memInfoSize) == memInfoSize;
                p = new IntPtr(p.ToInt64() + memInfo.RegionSize.ToInt64())) {

                if (memInfo.Protect == PAGE_NOACCESS) continue;

                /* 
                 * (memInfo.State == MEM_COMMIT || memInfo.State == MEM_FREE)
                    && (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_IMAGE
                    || memInfo.Type == MEM_MAPPED)
                 */

                if (memInfo.State == MEM_COMMIT
                    && memInfo.Type == MEM_PRIVATE) {
                    byte[] buffer = new byte[memInfo.RegionSize.ToInt64()];
                    int bytesRead = 0;

                    if (ReadProcessMemory(hProc, p, buffer, memInfo.RegionSize, ref bytesRead)) {
                        Array.Resize(ref buffer, bytesRead);
                        StringBuilder builder = new StringBuilder();

                        for (int i = 0; i < bytesRead; i++) {
                            bool cFlag = isChar(buffer[i]);

                            if (cFlag && uFlag && isUnicode && first > 0) {
                                isUnicode = false;
                                if (builder.Length > 0) builder.Remove(builder.Length - 1, 1);
                                builder.Append((char)buffer[i]);
                            }
                            else if (cFlag) builder.Append((char)buffer[i]);
                            else if (uFlag && buffer[i] == 0 && isChar(first) && isChar(second))
                                isUnicode = true;
                            else if (uFlag && buffer[i] == 0 && isChar(first)
                                && isChar(second) && builder.Length < 5) {
                                isUnicode = true;
                                builder = new StringBuilder();
                                builder.Append((char)first);
                            }
                            else {
                                if (builder.Length >= 5 && builder.Length <= 1500) {
                                    int l = builder.Length;
                                    if (isUnicode) l *= 2;
                                    dump.Add(builder.ToString());
                                }

                                isUnicode = false;
                                builder = new StringBuilder();
                            }
                        }
                    }
                }

            }

            Regex rgx = new Regex(@"^TRACE,.+,PcaClient,.+,(\w:\\.+.exe).+$", RegexOptions.Multiline);

            Console.WriteLine("PcaClient\n-----------------------\n");
            foreach (string d in dump) {
                MatchCollection matches = rgx.Matches(d);
                foreach (Match match in matches)
                    Console.WriteLine(match.Groups[1].Value);
            }

            Console.ReadLine();
        }

        static bool isChar(byte b) {
            return (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9;
        }
    }
}
