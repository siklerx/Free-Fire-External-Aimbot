using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DarknetHaxor_Aimbot
{
    public class Memory
    {

        public struct PatternData
        {
            public byte[] pattern { get; set; }
            public byte[] mask { get; set; }
        }

        public struct MemoryPage
        {
            public IntPtr Start;
            public int Size;

            public MemoryPage(IntPtr start, int size)
            {
                Start = start;
                Size = size;
            }
        }

        public int processId;

        public IntPtr _processHandle;


        public bool SetProcess(string[] processNames)
        {
            processId = 0;

            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                string processName = process.ProcessName;

                if (Array.Exists(processNames, name => name.Equals(processName, StringComparison.CurrentCultureIgnoreCase)))
                {
                    processId = process.Id;
                    break;
                }
            }

            if (processId <= 0)
            {
                return false;
            }

            _processHandle = OpenProcess(ProcessAccessFlags.AllAccess, false, processId);

            if (_processHandle == IntPtr.Zero)
            {
                MessageBox.Show("SIKLERX");
                return false;
            }

            return true;
        }


        public async Task<IEnumerable<long>> AoBScan(string bytePattern)
        {
            return await AobScan(bytePattern);
        }

        private async Task<IEnumerable<long>> AobScan(string pattern)
        {
            
            PatternData patternData = GetPatternDataFromPattern(pattern);

            List<long> addressRet = new List<long>();

            await Task.Run(() =>
            {
                List<MemoryPage> pages = new List<MemoryPage>();

                IntPtr lpAddress = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION page;

                while (VirtualQueryEx(_processHandle, lpAddress, out page, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))
                {
                    if (CanReadPage(page))
                    {
                        pages.Add(new MemoryPage(lpAddress, (int)page.RegionSize.ToUInt64()));
                    }
                    lpAddress = (IntPtr)((long)page.BaseAddress + (long)page.RegionSize);
                }

                int patternLength = patternData.pattern.Length;

                foreach (MemoryPage addresss in pages)
                {
                    byte[] memory = new byte[addresss.Size];

                    IntPtr bytesRead;
                    if (ReadProcessMemory(_processHandle, addresss.Start, memory,
                                            (IntPtr)addresss.Size, out bytesRead))
                    {


                        var iOffset = 0 - patternLength;
                        do
                        {
                            iOffset = FindPattern(memory, patternData.pattern, patternData.mask, iOffset + patternLength);

                            if (iOffset >= 0)
                            {
                                lock (addressRet)
                                {
                                    addressRet.Add((long)addresss.Start + iOffset);
                                }
                            }
                        } while (iOffset != -1);
                    }

                  
                }


            });
            return addressRet.OrderBy(c => c).AsEnumerable();
        }

        public bool CanReadPage(MEMORY_BASIC_INFORMATION page)
        {
            return page.State == MEM_COMMIT;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint PAGE_READWRITE = 0x04;

        private PatternData GetPatternDataFromPattern(string pattern)
        {
            string[] patternParts = pattern.Split(' ');

            PatternData patternData = new PatternData
            {
                pattern = patternParts.Select(s => s.Contains("??") ? (byte)0x00 : byte.Parse(s, NumberStyles.HexNumber)).ToArray(),
                mask = patternParts.Select(s => s.Contains("??") ? (byte)0x00 : (byte)0xFF).ToArray()
            };

            return patternData;
        }

        public bool AobReplace(long address, string bytePattern)
        {
            try
            {

                byte[] replacePattern = StringToByteArray(bytePattern);
                bool isWrite = WriteProcessMemory(_processHandle, (IntPtr)address, replacePattern, (IntPtr)replacePattern.Length, IntPtr.Zero);
                return isWrite;
            }
            catch (Exception ex)
            {

            }
            return false;
        }

        public string ReadString(long addressToRead, int size)
        {
            byte[] buffer = new byte[size];
            IntPtr bytesRead;

            bool readSuccess = ReadProcessMemory(_processHandle, (IntPtr)addressToRead, buffer, (IntPtr)size, out bytesRead);

            if (readSuccess && bytesRead.ToInt64() == size)
            {
                return BitConverter.ToString(buffer).Replace("-", " ");
            }
            return "";
        }

        private byte[] StringToByteArray(string hexString)
        {
            return hexString.Split(' ')
                            .Select(hex => byte.Parse(hex, NumberStyles.HexNumber))
                            .ToArray();
        }

        private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
        {
            int foundIndex = -1;

            if (body.Length <= 0 || pattern.Length <= 0 || start > body.Length - pattern.Length || pattern.Length > body.Length)
                return foundIndex;

            for (int bodyIndex = start; bodyIndex <= body.Length - pattern.Length; bodyIndex++)
            {
                if ((body[bodyIndex] & masks[0]) == (pattern[0] & masks[0]))
                {
                    bool match = true;
                    for (int patternIndex = pattern.Length - 1; patternIndex >= 1; patternIndex--)
                    {
                        if ((body[bodyIndex + patternIndex] & masks[patternIndex]) == (pattern[patternIndex] & masks[patternIndex]))
                            continue;

                        match = false;
                        break;
                    }

                    if (!match)
                        continue;

                    foundIndex = bodyIndex;
                    break;
                }
            }

            return foundIndex;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);

    }


    #region ProcessAccessFlags
    /// <summary>
    /// Process access rights list.
    /// </summary>
    [Flags]
    public enum ProcessAccessFlags
    {
        /// <summary>
        /// All possible access rights for a process object.
        /// </summary>
        AllAccess = 0x001F0FFF,
        /// <summary>
        /// Required to create a process.
        /// </summary>
        CreateProcess = 0x0080,
        /// <summary>
        /// Required to create a thread.
        /// </summary>
        CreateThread = 0x0002,
        /// <summary>
        /// Required to duplicate a handle using DuplicateHandle.
        /// </summary>
        DupHandle = 0x0040,
        /// <summary>
        /// Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken).
        /// </summary>
        QueryInformation = 0x0400,
        /// <summary>
        /// Required to retrieve certain information about a process (see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName). 
        /// A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.
        /// </summary>
        QueryLimitedInformation = 0x1000,
        /// <summary>
        /// Required to set certain information about a process, such as its priority class (see SetPriorityClass).
        /// </summary>
        SetInformation = 0x0200,
        /// <summary>
        /// Required to set memory limits using SetProcessWorkingSetSize.
        /// </summary>
        SetQuota = 0x0100,
        /// <summary>
        /// Required to suspend or resume a process.
        /// </summary>
        SuspendResume = 0x0800,
        /// <summary>
        /// Required to terminate a process using TerminateProcess.
        /// </summary>
        Terminate = 0x0001,
        /// <summary>
        /// Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
        /// </summary>
        VmOperation = 0x0008,
        /// <summary>
        /// Required to read memory in a process using <see cref="ReadProcessMemory"/>.
        /// </summary>
        VmRead = 0x0010,
        /// <summary>
        /// Required to write to memory in a process using WriteProcessMemory.
        /// </summary>
        VmWrite = 0x0020,
        /// <summary>
        /// Required to wait for the process to terminate using the wait functions.
        /// </summary>
        Synchronize = 0x00100000
    }
    #endregion


    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200)
    }

    public enum AllocationProtectEnum : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    public enum StateEnum : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }
    public enum TypeEnum : uint
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }
}