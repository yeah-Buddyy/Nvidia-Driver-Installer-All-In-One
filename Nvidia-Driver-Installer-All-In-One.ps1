# https://github.com/lord-carlos/nvidia-update/blob/master/nvidia.ps1
# https://github.com/farag2/NVidia-Driver-Update/blob/main/UpdateNVidiaDriver.ps1

# TODO
# Clean code
# Build functions for downloading needed programs automatically
# Block nvidia telemetry ips https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/block-telemetry.ps1 https://forums.guru3d.com/threads/is-nvidia-the-only-it-company-forcing-telemetry-to-its-costumers.436705/page-5#post-5887706 https://github.com/undergroundwires/privacy.sexy/blob/nvidia-308/src/application/collections/windows.yaml#L4400-L4725
# Instead of disabling Windows driver updates to prevent Windows from automatically installing the NVIDIA driver, boot into safe mode without a network and install the NVIDIA driver from there.

# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

### Edit here ###
$DDU = "$PSScriptRoot\DDU v18.0.7.7\Display Driver Uninstaller.exe"

# add a nvidia profile inspector profile
$enableNvidiaProfileInspector = $true
$NvidiaProfileInspector = "$PSScriptRoot\nvidiaProfileInspector2.4.0.4\nvidiaProfileInspector.exe"
$NvidiaProfileInspectorProfile = "$PSScriptRoot\nvidiaProfileInspector2.4.0.4\NvidiaBaseProfile.nip"

$disableUsbC = $true
$DevManView = "$PSScriptRoot\devmanview-x64\DevManView.exe"

# https://www.reddit.com/r/ValveIndex/comments/c72pg0/discussion_and_troubleshooting_for_index_hardware/esmjkz4/
$disableHdAudioSleepTimer = $true

# Disabling hdcp (required for DRM content)
$disableHdcp = $true

# Dont show the nvidia tray icon
$disableNvidiaTrayIcon = $true

# disable nvidia telemetry and do some tweaks
$enableTweaksandDisableTelemetry = $true

# Force TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Checking Windows version
if ([System.Version][Environment]::OSVersion.Version.ToString() -lt [System.Version]"10.0") {
    Write-Warning "Your Windows is unsupported. Upgrade to Windows 10 or higher" -Verbose
    Write-Host "Press any key to exit..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Checking Windows bitness
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Warning "Your Windows architecture is x86. x64 is required" -Verbose
    Write-Host "Press any key to exit..."
    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Creating a new temp folder
$tempNvidiaFolder = "$env:TEMP\NVIDIA-Clean"
if (-Not (Test-Path -Path $tempNvidiaFolder)) {
    New-Item -Path $tempNvidiaFolder -ItemType Directory -Force | Out-Null
}

function cleanUp {
    EnableAutoDriverUpdate

    Remove-Item -Path 'HKLM:\Software\AlreadyMetered' -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\Software\RebootDummyKey' -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKLM:\Software\TempDisableDriverUpdates' -Force -ErrorAction SilentlyContinue

    # Define the registry key path
    $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

    # Get all the property names (entries) in the registry key
    $entries = Get-ItemProperty -Path $registryPath | Select-Object -Property * | ForEach-Object { $_.PSObject.Properties.Name }

    # Iterate through each entry and remove it
    foreach ($entry in $entries) {
        if ($entry -ne "PSPath" -and $entry -ne "PSParentPath" -and $entry -ne "PSChildName" -and $entry -ne "PSDrive" -and $entry -ne "PSProvider") {
            Remove-ItemProperty -Path $registryPath -Name $entry -Force
        }
    }

    $Parameters = @{
    Path    = "$tempNvidiaFolder"
    Recurse = $true
    Force   = $true
    }
    Remove-Item @Parameters
}

function CheckInternetConnection {
    # Check the internet connection for max 60 seconds
    $number = 60
    $i = 1

    do{
        try {
            $pingresult = ping -4 -n 2 -w 700 8.8.8.8 | Select-String -Pattern 'TTL='
        }
        catch
        {
            Write-Warning "Internet error" -Verbose
        }

        Write-Verbose "Internet Connection Check Attempt Nr: $i" -Verbose
        Start-Sleep -Seconds 1

        if($pingresult -Match 'TTL=') {
            break
        }
        else {
            if($i -eq $number) {
                cleanUp
                Write-Warning "Please fix your internet and run the script again" -Verbose
                Write-Host "Press any key to exit..."
		        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }
        }
        $i++ 
    } while ($i -le $number)
}
CheckInternetConnection

$global:CurrentDriverVersion = ""
function nvidiaCheckCurrentDriverVersion {
    # Check current driver version
    Write-Verbose "Attempt to detect the current driver version installed" -Verbose
    try {
        [System.Version]$Driver = (Get-CimInstance -ClassName Win32_VideoController | Where-Object -FilterScript {$_.Name -match "NVIDIA"}).DriverVersion
        $global:CurrentDriverVersion = ("{0}{1}" -f $Driver.Build, $Driver.Revision).Substring(1).Insert(3,'.')
        Write-Verbose "Current version: $global:CurrentDriverVersion" -Verbose
    }
    catch {
        Write-Verbose "Unable to detect a compatible Nvidia device. Seems like its the first driver install or a clean install for you." -Verbose
    }
}
nvidiaCheckCurrentDriverVersion

function Download-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$url,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    try {
        # Create a WebClient object
        $webClient = New-Object System.Net.WebClient

        # Get the response stream from the URL
        $responseStream = $webClient.OpenRead($url)
        $totalSize = [int64]$webClient.ResponseHeaders["Content-Length"]

        # Create a file stream to write the downloaded file
        $fileStream = [System.IO.File]::Create($Destination)

        # Buffer for reading the response stream
        $buffer = New-Object byte[] 65536  # Increased buffer size for better efficiency
        $totalRead = 0
        $lastProgressUpdate = [datetime]::Now

        # Read from the response stream and write to the file stream
        while (($read = $responseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $read)
            $totalRead += $read

            # Update the progress bar less frequently
            if (([datetime]::Now - $lastProgressUpdate).TotalSeconds -ge 1) {
                $percentComplete = ($totalRead / $totalSize) * 100
                Write-Progress -Activity "Downloading file" -Status "$totalRead of $totalSize bytes" -PercentComplete $percentComplete
                $lastProgressUpdate = [datetime]::Now
            }
        }

        # Close streams
        $responseStream.Close()
        $fileStream.Close()

        # Check if the file was downloaded successfully
        if (Test-Path -Path $Destination) {
            Write-Verbose "Download successful. Proceed..." -Verbose
        } else {
            cleanUp
            Write-Warning "Download failed. The file was not found at the destination." -Verbose
            Write-Host "Press any key to exit..."
		    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } catch {
        cleanUp
        Write-Warning "Error downloading file from $url. Error: $_" -Verbose
        Write-Host "Press any key to exit..."
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } finally {
        # Ensure streams are closed in case of an error
        if ($responseStream) { $responseStream.Close() }
        if ($fileStream) { $fileStream.Close() }
    }
}

<#
function Test-WebsiteConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Website
    )

    try {
        # Test if the website is reachable
        $result = Test-Connection -ComputerName $Website -Count 1 -ErrorAction Stop

        # If Test-Connection succeeds, return success message
        if ($result) {
            Write-Verbose "`n$Website is reachable." -Verbose
        } else {
            Write-Verbose "`n$Website is not reachable." -Verbose
            Write-Host "Press any key to exit..."
		    $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } catch {
        # If Test-Connection fails (e.g., timeout, DNS resolution issue), catch the exception
        Write-Error "`nFailed to connect to $Website. Error: $_"
        Write-Host "Press any key to exit..."
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
#>

$global:archiverProgram = ""
function get7Zip {
    # Get the latest 7-Zip, if not already installed
    $7zipinstalled = $false
    $7ZipPathKey = "HKLM:\SOFTWARE\7-Zip\"
    
    if (Test-Path $7ZipPathKey) {
        $7ZipPath = (Get-ItemProperty -Path $7ZipPathKey -Name Path).Path
        $7ZipExe = Join-Path -Path $7ZipPath -ChildPath "7z.exe"
        
        if (Test-Path $7ZipExe) {
            $global:archiverProgram = $7ZipExe
            $7zipinstalled = $true
            Write-Verbose "7-Zip is already installed at $7ZipExe" -Verbose
        }
    }
    if (($7zipinstalled) -eq $false) {
        Write-Verbose "Sorry, but it looks like you don't have a supported archiver. We will download 7-zip for you" -Verbose

        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

        try {
            $Parameters = @{
                Uri             = "https://sourceforge.net/projects/sevenzip/best_release.json"
                UseBasicParsing = $true
                Verbose         = $true
                Headers         = @{
                    "User-Agent" = $UserAgent
                }
            }
            $bestRelease = (Invoke-RestMethod @Parameters).platform_releases.windows.filename.replace("exe", "msi")

            # Download the latest 7-Zip x64
            $Parameters = @{
                Uri             = "https://nchc.dl.sourceforge.net/project/sevenzip$($bestRelease)"
                OutFile         = "$tempNvidiaFolder\7Zip.msi"
                UseBasicParsing = $true
                Verbose         = $true
                Headers         = @{
                    "User-Agent" = $UserAgent
                }
            }
            Invoke-WebRequest @Parameters

            # Expand 7-Zip
            $Arguments = @(
                "/a `"$tempNvidiaFolder\7Zip.msi`""
                "TARGETDIR=`"$tempNvidiaFolder\7zip`""
                "/qb"
            )
            Start-Process "msiexec" -ArgumentList $Arguments -Wait

            # Delete the installer once it completes
            Remove-Item -Path "$tempNvidiaFolder\7Zip.msi" -Force

            if (Test-Path -Path "$tempNvidiaFolder\7zip\Files\7-Zip\7z.exe" -PathType Leaf) {
                $global:archiverProgram = "$tempNvidiaFolder\7zip\Files\7-Zip\7z.exe"
            } else {
                cleanUp
                Write-Warning "Please manually download and install 7-zip and restart the script" -Verbose
                Write-Host "Press any key to exit..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }

        }
        catch [System.Net.WebException] {
            cleanUp
            Write-Warning "Sourceforge.net or your internet connection is down, please manually download and install 7-zip and restart the script" -Verbose
            Write-Host "Press any key to exit..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit
        }
    }
}

# Temporary disable windows driver updates
function DisableAutoDriverUpdate {
    $networkKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
    $windowsUpdateKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    if (!(Test-Path $networkKeyPath -ErrorAction SilentlyContinue) -or 
        !(Test-Path $windowsUpdateKeyPath -ErrorAction SilentlyContinue)) {
        return
    }

    $val = Get-ItemProperty -Path $networkKeyPath -Name "Default", "Ethernet", "WiFi" -ErrorAction SilentlyContinue
    $val1 = Get-ItemProperty -Path $windowsUpdateKeyPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue

    if ($val.Default -eq 2 -and $val.Ethernet -eq 2 -and $val.WiFi -eq 2 -and $val1.NoAutoUpdate -eq 1) {
        Write-Verbose "It seems that your network is already configured as metered and against automatic updates." -Verbose
        New-Item 'HKLM:\Software\AlreadyMetered' -Force -ErrorAction SilentlyContinue
    } else {
        Write-Verbose "Temporary disable Windows Update driver offering" -Verbose
        New-Item 'HKLM:\Software\TempDisableDriverUpdates' -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath "$PSScriptRoot\Temporary-Block-Automatic-Driver-Install\Disable hijackers.cmd" -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
}

# Enable offering of drivers through Windows Update
function EnableAutoDriverUpdate {
    if ((Test-Path "HKLM:\Software\AlreadyMetered")) {
        Write-Verbose "No need to enable Windows Update driver offering as it was already disabled." -Verbose
        Remove-Item -Path "HKLM:\Software\AlreadyMetered" -Force
    } elseif ((Test-Path "HKLM:\Software\TempDisableDriverUpdates")) {
        Remove-Item -Path "HKLM:\Software\TempDisableDriverUpdates" -Force
        Write-Verbose "Enable driver availability through Windows Update" -Verbose
        Start-Process -FilePath "$PSScriptRoot\Temporary-Block-Automatic-Driver-Install\Undo everything.cmd" -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
}

$global:nvidiaConfig = ""
function IsLaptop {
    # https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
    # Mobile = 2
    $HardwareType = (Get-CimInstance -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
    if ($HardwareType -eq 2) {
        Write-Verbose "$Env:ComputerName is a Laptop" -Verbose
        # "nodejs" needed for gfexperience and rtx stuff, "PPC" needed for usb-c, "Display.Optimus" needed for notebooks
        if ($disableUsbC) {
            $global:nvidiaConfig = "nodejs Display.Optimus Display.Driver NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
        } else {
            $global:nvidiaConfig = "nodejs Display.Optimus Display.Driver NVI2 PhysX PPC EULA.txt ListDevices.txt setup.cfg setup.exe"
        }
    } else {
        Write-Verbose "$Env:ComputerName is a Desktop" -Verbose
        if ($disableUsbC) {
            $global:nvidiaConfig = "nodejs Display.Driver NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
        } else {
            $global:nvidiaConfig = "nodejs Display.Driver NVI2 PhysX PPC EULA.txt ListDevices.txt setup.cfg setup.exe"
        }
    }
}
IsLaptop

function downloadAndInstallNvidiaControlPanel {
    # Check if winget is already installed
    Write-Verbose "Check if winget is already installed to install the Nvidia Control Panel" -Verbose
    $WingetCmd = Get-Command "winget.exe" -Erroraction SilentlyContinue
    if ((Test-Path -Path '~\AppData\Local\Microsoft\WindowsApps\winget.exe' -PathType Leaf) -And $WingetCmd) {
        Write-Verbose "Winget is already installed Path: $env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" -Verbose
        CheckInternetConnection
        Write-Verbose "Downloading Nvidia Control Panel with winget" -Verbose
        Start-Process "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" -ArgumentList "install --id 9NF8H0H7WMLT --exact --source msstore --accept-package-agreements --accept-source-agreements" -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
    else {
        try {
            # Download and install Nvidia Control Panel Appx from store.rg-adguard.net
            Write-Verbose "Downloading Nvidia Control Panel Appx from store.rg-adguard.net" -Verbose
            CheckInternetConnection

            $apiUrl = "https://store.rg-adguard.net/api/GetFiles"

            $productUrl = "https://apps.microsoft.com/store/detail/nvidia-control-panel/9NF8H0H7WMLT" #Nvidia control panel

            $body = @{
                type = 'url'
                url  = $productUrl
                ring = 'RP'
                lang = [System.Globalization.CultureInfo]::CurrentCulture.Name
            }

            $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -ContentType 'application/x-www-form-urlencoded' -Body $body

            $raw | Select-String '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches|
            % { $_.Matches } |
            % { 
                $url = $_.Groups[1].Value
                $text = $_.Groups[2].Value
                
                if($text -match "_(x64|neutral).*appx(|bundle)$") {
                    $downloadFile = Join-Path $tempNvidiaFolder $text
                    if(!(Test-Path $downloadFile)) {
                        Invoke-WebRequest -Uri $url -OutFile $downloadFile
                    }
                }
            }
            $lastVersion = Get-ChildItem "$tempNvidiaFolder\*.appx" | sort-object -descending | select-object -First 1 -ExpandProperty Name
            Add-AppxPackage -Path "$tempNvidiaFolder\$lastVersion"
        }
        catch [System.Net.WebException] {
            Write-Warning "Could not download nvidia control panel from https://store.rg-adguard.net" -Verbose
        }
    }
}

function downloadNvidiaDriver {
    # Get the nvidia gpu device id
    try {
        $gpuDeviceID = (Get-CimInstance -Query "SELECT DeviceID FROM Win32_PNPEntity WHERE DeviceID LIKE '%PCI\\VEN_10DE%' AND (PNPClass = 'Display' OR Name = '3D Video Controller')" |
                        Select-Object -ExpandProperty DeviceID |
                        ForEach-Object {
                            if ($_ -match 'DEV_(\w{4}).*SUBSYS_(\w{8})') {
                                $deviceIdPart1 = $Matches[1]
                                return "$deviceIdPart1"
                            } else {
                                return ""
                            }
                        })

        if ($gpuDeviceID) {
            Write-Verbose "GPU Device ID: $gpuDeviceID" -Verbose
        } else {
            cleanUp
            Write-Warning "GPU Device ID not found." -Verbose
            Write-Host "Press any key to exit..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit
        }
    } catch {
        cleanUp
        Write-Warning "Error retrieving GPU Device ID: $_" -Verbose
        Write-Host "Press any key to exit..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }

    # Get nvidia driver
    try {
        # https://github.com/keylase/nvidia-patch/blob/master/tools/nv-driver-locator/gfe_get_driver.py
        #"dIDa": dev_id,                   # Device PCI IDs:
        #"osC": os_version,                # OS version (Windows 10)
        #"osB": os_build,                  # OS build
        #"is6": "1" if x86_64 else "0",    # 0 - 32bit, 1 - 64bit
        #"lg": str(language),              # Language code, 1031 = German, 1033 = English
        #"iLp": "1" if notebook else "0",  # System Is Laptop
        #"prvMd": "0",                     # Private Model?
        #"gcV": "3.18.0.94",               # GeForce Experience client version
        #"gIsB": "1" if beta else "0",     # Beta?
        #"dch": "1" if dch else "0",       # 0 - Standard Driver, 1 - DCH Driver
        #"upCRD": "1" if crd else "0",     # Searched driver: 0 - GameReady Driver, 1 - CreatorReady Driver
        #"isCRD": "1" if crd else "0",     # Installed driver: 0 - GameReady Driver, 1 - CreatorReady Driver

        $osVersionBuild = [System.Environment]::OSVersion.Version.Build

        $Parameters = @{
        Uri = "https://gfwsl.geforce.com/nvidia_web_services/controller.gfeclientcontent.NG.php/com.nvidia.services.GFEClientContent_NG.getDispDrvrByDevid/%7B%22dIDa%22:%5B%22" + $gpuDeviceID +  "_0_0_0%22%5D,%22osC%22:%2210.0%22,%22osB%22:%22" + $osVersionBuild + "%22,%22is6%22:%221%22,%22lg%22:%221033%22,%22iLp%22:%220%22,%22prvMd%22:%220%22,%22gcV%22:%220%22,%22gIsB%22:%220%22,%22dch%22:%220%22,%22upCRD%22:%220%22,%22isCRD%22:%220%22%7D"
        UseBasicParsing = $true
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        TimeoutSec = "60"
        ContentType = "application/json; charset=utf-8"
        Method = "GET"
        DisableKeepAlive = $true
        }
        $Data = Invoke-RestMethod @Parameters
    }
    catch [System.Net.WebException] {
        cleanUp
        Write-Warning "Could not get nvidia driver from https://gfwsl.geforce.com" -Verbose
        Write-Host "Press any key to exit..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }

    # Get latest driver version and driver download url
    if ($Data.DriverAttributes.Version) {
        [System.Version]$LatestVersion = $Data.DriverAttributes.Version
        Write-Verbose "Latest nvidia driver version is: $LatestVersion" -Verbose
        if ($global:CurrentDriverVersion -eq $LatestVersion) {
            Write-Verbose "Seems like you already have the latest nvidia driver installed.`nDo you still want to continue?" -Verbose
            $confirmation = Read-Host "(Y/N) Default is no"
            if ($confirmation -eq 'n') {
                cleanUp
                Write-Host "Bye Bye (-;"
                Write-Host "Press any key to exit..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }
        }

        if ($Data.DriverAttributes.DownloadURLAdmin) {
            $DownloadURLAdmin = $Data.DriverAttributes.DownloadURLAdmin
            Write-Verbose "Latest nvidia driver download url is: $DownloadURLAdmin" -Verbose

            # Download the driver
            Download-File -url $DownloadURLAdmin -Destination "$tempNvidiaFolder\nvidiaDriver.exe"
        } else {
            cleanUp
            Write-Warning "Could not get nvidia driver attributes from https://gfwsl.geforce.com" -Verbose
            Write-Host "Press any key to exit..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit
        }
    }
}

# Check if we are in normal boot or in safe boot
$checkBootMode = (Get-CimInstance win32_computersystem -Property BootupState).BootupState

if ($checkBootMode -like "*Normal boot*") {
    Write-Verbose "We are in a normal boot environment" -Verbose
    if ((-not (Test-Path 'HKLM:\Software\RebootDummyKey'))) {
        # Download and extract the nvidia driver first, if successfull we will start cleaning the current driver with DDU
        if (Test-Path -Path $tempNvidiaFolder) {
            Remove-item "$tempNvidiaFolder" -Recurse -Force
        }
        if (-Not (Test-Path -Path $tempNvidiaFolder)) {
            New-Item -Path $tempNvidiaFolder -ItemType Directory -Force | Out-Null
        }
        Write-Verbose "Downloading now the latest nvidia driver" -Verbose
        downloadNvidiaDriver

        get7Zip

        # Extracting installer
        # Based on 7-zip.chm
        Write-Verbose "Extracting the nvidia driver" -Verbose
        $Arguments = @(
            # Extracts files from an archive with their full paths in the current directory, or in an output directory if specified
            "x",
            # standard output messages. disable stream
            "-bso0",
            # progress information. redirect to stdout stream
            "-bsp1",
            # error messages. redirect to stdout stream
            "-bse1",
            # Overwrite All existing files without prompt
            "-aoa",
            # What to extract
            "$tempNvidiaFolder\nvidiaDriver.exe",
            # Extract these files and folders
            $global:nvidiaConfig,
            # Specifies a destination directory where files are to be extracted
            "-o`"$tempNvidiaFolder\NVidia`""
        )
        $Parameters = @{
            FilePath     = "$global:archiverProgram"
            ArgumentList = $Arguments
            NoNewWindow  = $true
            Wait         = $true
        }
        Start-Process @Parameters

        if (Test-Path -Path "$tempNvidiaFolder\NVidia\setup.exe" -PathType Leaf) {
            Write-Verbose "Unzipping driver successfully" -Verbose
        } else {
            cleanUp
            Write-Warning "Could not unzip the nvidia driver" -Verbose
            Write-Host "Press any key to exit..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit
        }

        if (Test-Path -Path "$tempNvidiaFolder\NVidia\setup.cfg" -PathType Leaf) {
            Write-Verbose "Remove unnecessary dependencies from setup.cfg" -Verbose
            Set-Content -Path "$tempNvidiaFolder\NVidia\setup.cfg" -Value (get-content -Path "$tempNvidiaFolder\NVidia\setup.cfg" | Select-String -Pattern 'EulaHtmlFile' -NotMatch)
            Set-Content -Path "$tempNvidiaFolder\NVidia\setup.cfg" -Value (get-content -Path "$tempNvidiaFolder\NVidia\setup.cfg" | Select-String -Pattern 'FunctionalConsentFile' -NotMatch)
            Set-Content -Path "$tempNvidiaFolder\NVidia\setup.cfg" -Value (get-content -Path "$tempNvidiaFolder\NVidia\setup.cfg" | Select-String -Pattern 'PrivacyPolicyFile' -NotMatch)
            Set-Content -Path "$tempNvidiaFolder\NVidia\setup.cfg" -Value (get-content -Path "$tempNvidiaFolder\NVidia\setup.cfg" | Select-String -Pattern 'enableTelemetry' -NotMatch)
        } else {
            Write-Warning "Could not find the nvidia setup.cfg" -Verbose
        }

        Write-Verbose "`We will restart your system in safe mode and clean your nvidia driver with DDU.`nDo you want to continue?" -Verbose
        $confirmation = Read-Host "(Y/N) Default is no"
        if ($confirmation -eq 'y') {
            DisableAutoDriverUpdate
            # Create a runonce key in the registry to run the script automatically when you restart in safe mode.
            # By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk (*) to force the program to run even in Safe mode.
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force -Name "*RebootSafeMode*" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            # Reboot to safe mode with networking
            Start-Process "$env:SystemRoot\System32\cmd.exe"-ArgumentList '/s,/c,bcdedit /set {current} safeboot network & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue
            exit
        }
        else {
            cleanUp
            Write-Host "Bye Bye (-;"
            Write-Host "Press any key to exit..."
            $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit
        }
    }
}

if ($checkBootMode -like "*Fail-safe*") {
    Write-Verbose "We are in a safe boot environment" -Verbose
    # Driver uninstall with DDU, only if the system is in safe boot
    if ((-not (Test-Path 'HKLM:\Software\RebootDummyKey'))) {
        Write-Verbose "DDU Driver Uninstaller now running" -Verbose
        Start-Process -FilePath "$DDU" -ArgumentList {"-silent", "-cleannvidia", "-RemovePhysx", "-RemoveGFE", "-RemoveNVBROADCAST", "-RemoveNVCP"} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        # Create a dummy registry key needed to continue the script after a reboot.
        New-Item 'HKLM:\Software\RebootDummyKey' -Force
        # Create a runonce key in the registry to run the script automatically after rebooting to normal boot.
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force -Name "RebootNormalMode" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        # Reboot to normal mode
        Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/s,/c,bcdedit /deletevalue {current} safeboot & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue
        exit
    }
}

if ($checkBootMode -like "*Normal boot*") {
    # Download and install nvidia driver
    if ((Test-Path 'HKLM:\Software\RebootDummyKey')) {
        Write-Verbose "Starting Nvidia install script" -Verbose
        Remove-Item -Path "HKLM:\Software\RebootDummyKey" -Force

        # Installing drivers
        Write-Verbose "Installing the nvidia driver" -Verbose
        $Arguments = @("-passive", "-noreboot", "-noeula", "-nofinish", "-clean", "-enableTelemetry:false", "-gfexperienceinitiated:false")
        Start-Process -FilePath "$tempNvidiaFolder\NVidia\setup.exe" -ArgumentList $Arguments -Wait

        downloadAndInstallNvidiaControlPanel

        if ($disableNvidiaTrayIcon) {
            # Dont show the nvidia tray icon
            Write-Verbose "Disable the nvidia tray icon" -Verbose
            # Check if the registry key exists, if not, create it
            if (-not (Test-Path -Path "HKCU:\SOFTWARE\NVIDIA Corporation\NvTray")) {
                New-Item -Path "HKCU:\SOFTWARE\NVIDIA Corporation\NvTray" -Force | Out-Null
            }
            # Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\NvTray" -Name "StartOnLogin" -Value "0" -Type DWord -Force
            New-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\NvTray" -Name "StartOnLogin" -Value "0" -PropertyType DWord -Force | Out-Null
        }

        if ($disableHdcp) {
            # Disabling hdcp (required for DRM content)
            Write-Verbose "Disabling hdcp" -Verbose
            $regPathHdcp = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\*" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DriverDesc -match "NVIDIA" } | 
                    Select-Object -ExpandProperty PSPath

            if ($regPathHdcp) {
                # Set-ItemProperty -Path $regPathHdcp -Name "RMHdcpKeyglobZero" -Value 1 -Type DWord -Force
                New-ItemProperty -Path $regPathHdcp -Name "RMHdcpKeyglobZero" -Value 1 -PropertyType DWord -Force | Out-Null
            }
        }

        # disable HDAudio sleep timer
        if ($disableHdAudioSleepTimer) {
            # Disable HDAudio sleep timer https://www.reddit.com/r/ValveIndex/comments/c72pg0/discussion_and_troubleshooting_for_index_hardware/esmjkz4/
            Write-Verbose "Disabling HDAudio sleep timer" -Verbose
            Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList {/c for /F "tokens=*" %i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /t REG_BINARY /s /e /f "IdlePowerState"^| findstr "HK"') do ( reg add "%i" /v "ConservationIdleTime" /t REG_BINARY /d "ffffffff" /f )} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList {/c for /F "tokens=*" %i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /t REG_BINARY /s /e /f "IdlePowerState"^| findstr "HK"') do ( reg add "%i" /v "PerformanceIdleTime" /t REG_BINARY /d "ffffffff" /f )} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList {/c for /F "tokens=*" %i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /t REG_BINARY /s /e /f "IdlePowerState"^| findstr "HK"') do ( reg add "%i" /v "IdlePowerState" /t REG_BINARY /d "00000000" /f )} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }

        if ($disableUsbC) {
            # Disabling usb-c
            # name in devmanview @System32\drivers\usbxhci.sys,#1073807361;%1 USB %2 eXtensible-Hostcontroller – %3 (Microsoft);(NVIDIA,3.10,1.10)
            Write-Verbose "Disabling USB-C" -Verbose
            Start-Process -FilePath "$DevManView" -ArgumentList {/disable "*(Microsoft);(NVIDIA,3.10,1.10)" "/use_wildcard"} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }

        if ($enableNvidiaProfileInspector) {
            # Install nvidiaprofileinspector profile
            Write-Verbose "Install nvidiaprofileinspector profile" -Verbose
            $argument = '-silent'
            # If the path contains spaces or special characters, it should be wrapped in double quotes
            $escapedPath = "`"$NvidiaProfileInspectorProfile`""
            # Combine the escaped path and other arguments into the ArgumentList array
            $argumentList = "$escapedPath $argument"
            Start-Process -FilePath "$NvidiaProfileInspector" -ArgumentList $argumentList -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }
        
        # Clean up
        cleanUp

        if ($enableTweaksandDisableTelemetry) {
            if (Test-Path -Path "$PSScriptRoot\Tweaks-And-Telemetry\Tweaks-And-Telemetry.ps1" -PathType Leaf) {
                Write-Verbose "Adding some nvidia tweaks and removing telemetry after reboot" -Verbose
                Set-Itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" "NvidiaTweaksAndTelemetry" ('Powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File ' + "`"$PSScriptRoot\Tweaks-And-Telemetry\Tweaks-And-Telemetry.ps1`" -Verb RunAs") -Force
            }
        }
            
        # Driver installed, requesting a reboot
        Write-Verbose "Driver installed. You may need to reboot to finish installation." -Verbose
        Write-Verbose "Would you like to reboot now?" -Verbose
        $Readhost = Read-Host "(Y/N) Default is no"
        Switch ($ReadHost) {
            Y { Write-Verbose "Rebooting now.."; Start-Sleep -Seconds 2; Restart-Computer -Verbose }
            N { Write-Verbose "Bye Bye :-)"; Start-Sleep -Seconds 2 -Verbose }
            Default { Write-Verbose"Bye Bye :-)"; Start-Sleep -Seconds 2 -Verbose }
        }
        # End of script
        exit
    }
}

exit
