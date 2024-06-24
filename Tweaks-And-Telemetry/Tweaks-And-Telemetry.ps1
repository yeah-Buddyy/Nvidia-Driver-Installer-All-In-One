# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# enable msi mode
Write-Verbose "enable msi mode" -Verbose
$VideoCardID = (Get-CimInstance win32_VideoController) | Where-Object { $_.PNPDeviceID -like "PCI\VEN_*"}
if (-Not (Test-Path -Path "HKLM:\SYSTEM\ControlSet001\Enum\$($VideoCardID.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties")) {
    New-Item "HKLM:\SYSTEM\ControlSet001\Enum\$($VideoCardID.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Enum\$($VideoCardID.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Name MSISupported -Value 1 -PropertyType DWORD -Force
} else {
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Enum\$($VideoCardID.PNPDeviceID)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Name MSISupported -Value 1 -PropertyType DWORD -Force
}

# Remove Nvidia Telemtery
# Turn off services
Write-Verbose "Remove Nvidia Telemtery" -Verbose
Get-Service -ServiceName "NvTelemetryContainer" | Stop-Service | Set-Service -StartupType Disabled -Erroraction SilentlyContinue

# Remove diagnostics tracking scheduled tasks
Unregister-ScheduledTask -TaskName NvProfile* -Confirm:$false
Unregister-ScheduledTask -TaskName NvTmMon* -Confirm:$false
Unregister-ScheduledTask -TaskName NvTmRep* -Confirm:$false
Unregister-ScheduledTask -TaskName NvDriverUpdateCheck* -Confirm:$false
Unregister-ScheduledTask -TaskName NvNode* -Confirm:$false

# Stop processes matching NVDisplay.Container.exe*
Get-Process -Name "NVDisplay.Container*" | Stop-Process -Force

# Turn off Ansel
Start-Process -FilePath "$env:ProgramFiles\NVIDIA Corporation\Ansel\Tools\NvCameraEnable.exe" -ArgumentList off -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue

# Specify the root path where you want to start searching
$rootPath = "$env:SystemRoot\System32\DriverStore\FileRepository"

# Use Get-ChildItem with -Recurse to search recursively
$results = Get-ChildItem -Path $rootPath -Filter "NvCameraEnable.exe" -File -Recurse

# Output the results
if ($results.Count -gt 0) {
    foreach ($file in $results) {
        Write-Output "Found: $($file.FullName)"
        Start-Process -FilePath "$($file.FullName)" -ArgumentList off -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
} else {
    Write-Output "No NvCameraEnable.exe found."
}

# Delete telemetry logs
# Specify the root path where you want to start searching
$rootPath1 = "$env:SystemRoot\System32\DriverStore\FileRepository"

# Directories to search for
$searchDirs = @("NvTelemetry", "NvCamera", "NVWMI")
# $outputArray = @()

foreach ($dir in $searchDirs) {
    # Use Get-ChildItem with -Recurse to search recursively
    $results1 = Get-ChildItem -Path $rootPath1 -Filter "$dir" -Directory -Recurse -ErrorAction SilentlyContinue

    # Output the results
    if ($results1) {
        foreach ($folder in $results1) {
            Write-Host "Found: $($folder.FullName)"
            # $outputArray += $folder.FullName
            if ((Get-WinSystemLocale).Name -eq "de-DE") {
                takeown.exe /a /r /d J /f "$($folder.FullName)"
                icacls.exe "$($folder.FullName)" /T /C /GRANT:r "*S-1-5-32-544:(F)"
                Remove-Item -Path "$($folder.FullName)" -Force -Recurse -ErrorAction SilentlyContinue
            } else {
                takeown.exe /a /r /d Y /f "$($folder.FullName)"
                icacls.exe "$($folder.FullName)" /T /C /GRANT:r "*S-1-5-32-544:(F)"
                Remove-Item -Path "$($folder.FullName)" -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-Host "No $dir found."
    }
}

# Output the results as a string array
# $outputArray | Write-Host

# Specify the root path where you want to start searching
$rootPath2 = "$env:SystemRoot\System32\DriverStore\FileRepository"

# Files to search for
$searchFiles = @("nvtopps.dll", "dlsargs.xml", "dlsnetparams.csv", "nvgwls.exe", "nvtopps.db3", "nvprofileupdaterplugin.dll", "_DisplayDriverRAS.dll", "NvTelemetry*.dll", "NvContainerRecovery.bat", "NvTelemetryContainerRecovery.bat")

foreach ($file in $searchFiles) {
    # Use Get-ChildItem with -Recurse to search recursively
    $results2 = Get-ChildItem -Path $rootPath2 -Filter "$file" -File -Recurse -ErrorAction SilentlyContinue

    # Output the results
    if ($results2) {
        foreach ($myfile in $results2) {
            Write-Host "Found: $($myfile.FullName)"
            $myPath = Split-Path "$($myfile.FullName)" -Parent
            if ((Get-WinSystemLocale).Name -eq "de-DE") {
                takeown.exe /a /r /d J /f "$myPath"
                icacls.exe "$myPath" /T /C /GRANT:r "*S-1-5-32-544:(F)"
                Remove-Item -Path "$($myfile.FullName)" -Force -ErrorAction SilentlyContinue
            } else {
                takeown.exe /a /r /d Y /f "$myPath"
                icacls.exe "$myPath" /T /C /GRANT:r "*S-1-5-32-544:(F)"
                Remove-Item -Path "$($myfile.FullName)" -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-Host "No $file found."
    }
}

Remove-Item -Path "$env:ProgramData\NVIDIA\NvTelemetryContainer.log*" -Force -ErrorAction SilentlyContinue
remove-item -path "$env:ProgramFiles\NVIDIA Corporation\Display.NvContainer\plugins\LocalSystem\DisplayDriverRAS" -Force -ErrorAction SilentlyContinue -Recurse
remove-item -path "$env:ProgramFiles\NVIDIA Corporation\DisplayDriverRAS" -Force -ErrorAction SilentlyContinue -Recurse
remove-item -path "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" -Force -ErrorAction SilentlyContinue -Recurse
remove-item -path "${env:ProgramFiles(x86)}\NVIDIA Corporation\NvTelemetry" -Force -ErrorAction SilentlyContinue -Recurse
Remove-Item -Path "$env:ProgramData\NVIDIA Corporation\NvTelemetry" -Force -ErrorAction SilentlyContinue -Recurse
Remove-Item -Path "$env:ProgramData\NVIDIA Corporation\NvProfileUpdaterPlugin" -Force -ErrorAction SilentlyContinue -Recurse
Remove-Item -Path "$env:ProgramData\NVIDIA Corporation\nvtopps" -Force -ErrorAction SilentlyContinue -Recurse
Remove-Item -Path "$env:ProgramData\NVIDIA Corporation\DisplayDriverRAS\NvTelemetry" -Force -ErrorAction SilentlyContinue -Recurse

if (-not (Test-Path -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS")) {
    New-Item -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Force
}
if (-not (Test-Path -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client")) {
    New-Item -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Force
}
if (-not (Test-Path -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData")) {
    New-Item -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Force
}
if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name "EnableRID44231" -Value "0" -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name "EnableRID64640" -Value "0" -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" -Name "EnableRID66610" -Value "0" -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name "OptInOrOutPreference" -Value "0" -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name "@" -Value "0" -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Value "0" -PropertyType DWord -Force

if (Test-Path -Path "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL") {
    rundll32.exe "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32.exe "$env:ProgramFiles\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
}

# Set Enable/Disable NVIDIA-Display-Container to Context Menu
Set-Content "$env:ProgramData\Enable-NVIDIA-Display-Container.ps1" @'
    # .Net methods for hiding/showing the console in the background
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    function Hide-Console
    {
        $consolePtr = [Console.Window]::GetConsoleWindow()
        #0 hide
        [Console.Window]::ShowWindow($consolePtr, 0)
    }
    Hide-Console

    # Run as Admin
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

    Write-Verbose -Message "Enable NVIDIA Display Container Service" -Verbose
    Get-Service -ServiceName "NVDisplay.ContainerLocalSystem" | Start-Service | Set-Service -StartupType Automatic -Erroraction SilentlyContinue

    exit
'@

Set-Content "$env:ProgramData\Disable-NVIDIA-Display-Container.ps1" @'
    # .Net methods for hiding/showing the console in the background
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    function Hide-Console
    {
        $consolePtr = [Console.Window]::GetConsoleWindow()
        #0 hide
        [Console.Window]::ShowWindow($consolePtr, 0)
    }
    Hide-Console

    # Run as Admin
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

    Add-Type -AssemblyName System.Windows.Forms

    # Define the registry path and key
    $registryPath = "HKCU:\Software\nvidiadisplaycontainermsgbox"
    $registryKey = "msgboxShown"

    # Check if the msg box has been shown before
    $msgboxShown = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue

    if ($null -eq $msgboxShown) {
        # Msg box not shown yet, show the message box
        $message = "Disabling the 'NVIDIA Display Container LS' service will stop the NVIDIA Control Panel from working." +
                "`nIt will most likely break other NVIDIA driver features as well." +
                "`nThese scripts are aimed at users that have a stripped driver, and people that barely touch the NVIDIA Control Panel." +
                "`nYou can enable the NVIDIA Control Panel and the service again by running the enable script."
                
        [System.Windows.Forms.MessageBox]::Show($message, "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

        # Create the registry key to indicate that the msg box has been shown
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name $registryKey -Value $true
    } else {
        Write-Host "Msg box has already been shown."
    }

    Write-Verbose -Message "Disable NVIDIA Display Container Service" -Verbose
    Get-Service -ServiceName "NVDisplay.ContainerLocalSystem" | Stop-Service -Force | Set-Service -StartupType Disabled -Erroraction SilentlyContinue

    exit
'@

if (Test-Path -Path "$env:ProgramData\Enable-NVIDIA-Display-Container.ps1" -PathType Leaf) {
    if (Test-Path -Path "$env:ProgramData\Disable-NVIDIA-Display-Container.ps1" -PathType Leaf) {
        if (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer") {
            Remove-Item "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer" -Force -Recurse
        }
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer" -Force
        }
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001" -Force
        }
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001\command")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001\command" -Force
        }
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002" -Force
        }
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002\command")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002\command" -Force
        }
        Remove-Item -Path 'HKCU:\Software\nvidiadisplaycontainermsgbox' -Force -ErrorAction SilentlyContinue
        Copy-Item -Path "$PSScriptRoot\Tweaks-And-Telemetry\Nvidia.ico" -Destination "$env:ProgramData\Nvidia.ico" -Force
        if (Test-Path -Path "$env:ProgramData\Nvidia.ico" -PathType Leaf) {
            New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\NVIDIAContainer" -Force -Name "Icon" -PropertyType "String" -Value `"$env:ProgramData\Nvidia.ico`"
        }
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\NVIDIAContainer" -Force -Name "MUIVerb" -PropertyType "String" -Value "NVIDIA Container"
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\NVIDIAContainer" -Force -Name "Position" -PropertyType "String" -Value "Bottom"
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\NVIDIAContainer" -Force -Name "SubCommands" -PropertyType "String" -Value ""
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001" -Force -Name "HasLUAShield" -PropertyType "String" -Value ""
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001" -Force -Name "MUIVerb" -PropertyType "String" -Value "Enable NVIDIA Display Container"
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer001\command" -Force -Name "(default)" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$env:ProgramData\Enable-NVIDIA-Display-Container.ps1`""
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002" -Force -Name "HasLUAShield" -PropertyType "String" -Value ""
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002" -Force -Name "MUIVerb" -PropertyType "String" -Value "Disable NVIDIA Display Container"
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\DesktopBackground\shell\NVIDIAContainer\shell\NVIDIAContainer002\command" -Force -Name "(default)" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$env:ProgramData\Disable-NVIDIA-Display-Container.ps1`""
    }
}

exit
