using System;
using System.Runtime.InteropServices;

namespace Tibia.Utilities
{
    public static class WinAPI
    {
        public const uint CREATE_SUSPENDED = 0x00000004;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
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

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            private ushort reserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort dwProcessorLevel;
            public ushort dwProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string imageName, string cmdLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool boolInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpszCurrentDir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, MemoryProtection flNewProtect, ref MemoryProtection lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesWritten);

        public static T ReadUnmanagedStructure<T>(IntPtr hProcess, IntPtr lpAddr)
        {
            var array = new byte[Marshal.SizeOf(typeof(T))];
            ReadProcessMemory(hProcess, lpAddr, array, new UIntPtr((uint)array.Length), IntPtr.Zero);
            var gCHandle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var result = (T)((object)Marshal.PtrToStructure(gCHandle.AddrOfPinnedObject(), typeof(T)));
            gCHandle.Free();
            return result;
        }

        public static IntPtr GetBaseAddress(IntPtr hProcess)
        {
            SYSTEM_INFO sYSTEM_INFO;
            GetSystemInfo(out sYSTEM_INFO);

            var lpMinimumApplicationAddress = sYSTEM_INFO.lpMinimumApplicationAddress;
            var mEMORY_BASIC_INFORMATION = default(MEMORY_BASIC_INFORMATION);
            var dwLength = (uint)Marshal.SizeOf(mEMORY_BASIC_INFORMATION);

            while (lpMinimumApplicationAddress.ToInt64() < sYSTEM_INFO.lpMaximumApplicationAddress.ToInt64())
            {
                if (!VirtualQueryEx(hProcess, lpMinimumApplicationAddress, out mEMORY_BASIC_INFORMATION, dwLength))
                {
                    return IntPtr.Zero;
                }

                if (mEMORY_BASIC_INFORMATION.Type == 16777216u && mEMORY_BASIC_INFORMATION.BaseAddress == mEMORY_BASIC_INFORMATION.AllocationBase && (mEMORY_BASIC_INFORMATION.Protect & 256u) != 256u)
                {
                    var iMAGE_DOS_HEADER = ReadUnmanagedStructure<IMAGE_DOS_HEADER>(hProcess, lpMinimumApplicationAddress);
                    if (iMAGE_DOS_HEADER.e_magic == 23117)
                    {
                        var lpAddr = new IntPtr(lpMinimumApplicationAddress.ToInt64() + (long)(iMAGE_DOS_HEADER.e_lfanew + 4));
                        if ((ReadUnmanagedStructure<IMAGE_FILE_HEADER>(hProcess, lpAddr).Characteristics & 2) == 2)
                        {
                            return lpMinimumApplicationAddress;
                        }
                    }
                }

                lpMinimumApplicationAddress = new IntPtr(mEMORY_BASIC_INFORMATION.BaseAddress.ToInt64() + mEMORY_BASIC_INFORMATION.RegionSize.ToInt64());
            }

            return lpMinimumApplicationAddress;
        }
    }
}
