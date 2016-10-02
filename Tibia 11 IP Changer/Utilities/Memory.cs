using System;
using System.Text;

namespace Tibia.Utilities
{
    public static class Memory
    {
        public static uint ScanBytes(byte[] buffer, byte[] value)
        {
            var len = value.Length;
            var end = buffer.Length - len;

            for (int i = 0; i < end; ++i)
            {
                int j = 0;

                for (; j < len && buffer[i + j] == value[j]; ++j) ;

                if (j == len)
                {
                    return (uint)i;
                }
            }

            return 0;
        }

        public static uint ScanString(byte[] buffer, string value)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            return ScanBytes(buffer, bytes);
        }

        public static byte[] ReadBytes(IntPtr processHandle, long address, uint bytesToRead)
        {
            IntPtr ptrBytesRead;
            var buffer = new byte[bytesToRead];
            WinAPI.ReadProcessMemory(processHandle, new IntPtr(address), buffer, bytesToRead, out ptrBytesRead);
            return buffer;
        }

        public static string ReadString(IntPtr processHandle, long address)
        {
            var s = string.Empty;
            var temp = ReadBytes(processHandle, address++, 1)[0];
            while (temp != 0)
            {
                s += (char)temp;
                temp = ReadBytes(processHandle, address++, 1)[0];
            }

            return s;
        }

        public static bool WriteBytes(IntPtr processHandle, long address, byte[] bytes, uint length)
        {
            IntPtr bytesWritten;
            var result = WinAPI.WriteProcessMemory(processHandle, new IntPtr(address), bytes, length, out bytesWritten);
            return result != 0;
        }

        public static bool WriteString(IntPtr processHandle, long address, string value)
        {
            IntPtr bytesWritten;
            WinAPI.MemoryProtection oldProtection = 0;
            var enc = new ASCIIEncoding();
            var bytes = enc.GetBytes(value);
            WinAPI.VirtualProtectEx(processHandle, new IntPtr(address), new IntPtr(bytes.Length), WinAPI.MemoryProtection.ExecuteReadWrite, ref oldProtection);
            var result = WinAPI.WriteProcessMemory(processHandle, new IntPtr(address), bytes, (uint)bytes.Length, out bytesWritten);
            WinAPI.VirtualProtectEx(processHandle, new IntPtr(address), new IntPtr(bytes.Length), oldProtection, ref oldProtection);
            return (result != 0);
        }
    }
}
