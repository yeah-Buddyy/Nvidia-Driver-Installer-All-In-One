# https://github.com/lord-carlos/nvidia-update/blob/master/nvidia.ps1
# https://github.com/farag2/NVidia-Driver-Update/blob/main/UpdateNVidiaDriver.ps1

# TODO
# Block nvidia telemetry ips https://github.com/W4RH4WK/Debloat-Windows-10/blob/master/scripts/block-telemetry.ps1 https://forums.guru3d.com/threads/is-nvidia-the-only-it-company-forcing-telemetry-to-its-costumers.436705/page-5#post-5887706 https://github.com/undergroundwires/privacy.sexy/blob/nvidia-308/src/application/collections/windows.yaml#L4400-L4725

# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process $env:WinDir\System32\WindowsPowershell\v1.0\powershell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

### Edit here ###

# add a nvidia profile inspector profile
$enableNvidiaProfileInspector = $true
$NvidiaProfileInspectorProfile = "$PSScriptRoot\NvidiaBaseProfile.nip"

$disableUsbC = $true

# https://www.reddit.com/r/ValveIndex/comments/c72pg0/discussion_and_troubleshooting_for_index_hardware/esmjkz4/
$disableHdAudioSleepTimer = $true

# Disabling hdcp (required for DRM content)
$disableHdcp = $true

# Dont show the nvidia tray icon
$disableNvidiaTrayIcon = $true

# disable nvidia telemetry and enable msi mode
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
    Write-Verbose "Cleaning up..." -Verbose

    RestoreAutoDriverUpdate

    Remove-Item -Path 'HKLM:\Software\RebootDummyKey' -Force -ErrorAction SilentlyContinue

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

# Define path to the INI file
$iniFilePath = "$env:Temp\OriginalDriverSettings.ini"

# Helper function to save original settings
function Export-OriginalSettings {
    param (
        [string]$RegistryPath,
        [string]$ValueName
    )

    # Check if the registry value exists and export it if so
    if (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue) {
        $originalValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName).$ValueName
        Add-Content -Path $iniFilePath -Value "$RegistryPath`|$ValueName=$originalValue"
    } else {
        Add-Content -Path $iniFilePath -Value "$RegistryPath`|$ValueName=$originalValue|Delete"
    }
}

function DisableAutoDriverUpdate {
    # Preventing windows from automatically installing nvidia driver

    Write-Verbose "Saving original registry settings to $iniFilePath..." -Verbose

    if (Test-Path -Path $iniFilePath -PathType Leaf) {
        Remove-Item -Path "$iniFilePath" -Force
    }

    # List of registry keys and values to back up
    $settingsToBackup = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"; Name = "PreventDeviceMetadataFromNetwork" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching"; Name = "DontPromptForWindowsUpdate" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching"; Name = "DontSearchWindowsUpdate" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching"; Name = "DriverUpdateWizardWuSearchEnabled" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching"; Name = "SearchOrderConfig" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "ExcludeWUDriversInQualityUpdate" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"; Name = "SearchOrderConfig" }
    )

    #@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"; Name = "Default" }
    #@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"; Name = "Ethernet" }
    #@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"; Name = "WiFi" }

    # Export current values to INI file
    foreach ($setting in $settingsToBackup) {
        Export-OriginalSettings -RegistryPath $setting.Path -ValueName $setting.Name
    }

    Write-Verbose "Disabling driver offering through Windows Update..." -Verbose

    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1

    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0

    # metered connection, cant edit with admin rights because owner is trustedinstaller
    #If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost")) {
        #New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "Default" -Type DWord -Value 2
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "Ethernet" -Type DWord -Value 2
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -Name "WiFi" -Type DWord -Value 2
}

function RestoreAutoDriverUpdate {
    # To revert settings, load from the INI file and restore values
    if (Test-Path -Path $iniFilePath -PathType Leaf) {
        $settings = Get-Content -Path $iniFilePath
        foreach ($setting in $settings) {
            $parts = $setting -split "\|"
            $registryPath = $parts[0]
            $nameValue = $parts[1] -split "="
            if ($parts[2] -match "Delete") {
                $valueName = $nameValue[0]
                Remove-ItemProperty $registryPath -Name $valueName -Force
            } else {
                $valueName = $nameValue[0]
                $valueData = [int]$nameValue[1]
                Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Force
            }
        }
        Write-Verbose "Original settings restored from $iniFilePath." -Verbose
        Remove-Item -Path "$iniFilePath" -Force
    } else {
        Write-Warning "INI file not found. Original settings cannot be restored."
    }
}


function Download-GithubRelease {
    param (
        [string]$Repository,               # e.g., "Orbmu2k/nvidiaProfileInspector"
        [string]$FilePattern,              # Pattern to match the release file
        [string]$DestinationPath,          # Destination folder for the download
        [string]$ExpectedHash = $null      # Optionally, you can pass a hash to verify the downloaded file
    )

    CheckInternetConnection

    # Check and create destination path if it doesn't exist
    if (-not (Test-Path $DestinationPath)) {
        try {
            New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Could not create path '$DestinationPath'. Exiting." -Verbose
            return
        }
    }

    # Get the release assets from GitHub
    $releasesUri = "https://api.github.com/repos/$Repository/releases"
    $assets = (Invoke-RestMethod -Method GET -Uri $releasesUri).assets

    # Find the file that matches the pattern
    $downloadUrl = $assets.browser_download_url

    foreach ($url in $downloadUrl) {
        if ($url -like "$FilePattern") {
            $foundUrl = $url
            break
        }
    }

    if (-not $foundUrl) {
        Write-Warning "File matching pattern '$FilePattern' not found in the latest release." -Verbose
        return
    }

    # Define the download file path
    $outFile = Split-Path -Leaf $foundUrl
    $outPath = Join-Path -Path $DestinationPath -ChildPath $outFile

    # Download the file
    try {
        Write-Verbose "Downloading file from $foundUrl..." -Verbose
        (New-Object Net.WebClient).DownloadFile($foundUrl, $outPath)
        Write-Verbose "Downloaded to $outPath" -Verbose

        # If expected hash is provided, verify the downloaded file's hash
        if ($ExpectedHash) {
            try {
                $actualHash = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash
                if ($actualHash -ne $ExpectedHash) {
                    Write-Warning "Hash mismatch for '$outPath'. Expected: $ExpectedHash, Actual: $actualHash" -Verbose
                    return
                } else {
                    Write-Verbose "Hash verification successful for '$outPath'" -Verbose
                }
            } catch {
                Write-Warning "Hash verification failed for '$outPath': $_" -Verbose
            }
        }
    } catch {
        Write-Warning "Error downloading file: $_" -Verbose
        return
    }

    # Check if the file is an archive and extract it
    if ($outPath -imatch "\.(zip|rar|7z)$") {
        try {
            Write-Verbose "Extracting file: $outPath" -Verbose
            if ($outPath -like "*.zip") {
                Expand-Archive -Path $outPath -DestinationPath $DestinationPath -Force
            }
            #} elseif ($outPath -like "*.rar" -or $outPath -like "*.7z") {
                # Requires 7-Zip to be installed on your system
                #$sevenZipPath = "C:\Program Files\7-Zip\7z.exe"  # Adjust path to your 7z.exe
                #& $sevenZipPath x $outPath -o$DestinationPath -y
            #}
            Write-Verbose "Extraction completed!" -Verbose
        } catch {
            Write-Warning "Error during extraction: $_" -Verbose
        } finally {
            Remove-Item $outPath -Force
        }
    } else {
        Write-Verbose "Downloaded file is not an archive." -Verbose
    }
}

function nvidiaCheckCurrentDriverVersion {
    # Check current driver version
    Write-Verbose "Attempt to detect the current driver version installed" -Verbose
    try {
        [System.Version]$Driver = (Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | Where-Object -FilterScript {$_.Name -match "NVIDIA"}).DriverVersion
        # Construct the version string
        $CurrentDriverVersion = ("{0}{1}" -f $Driver.Build, $Driver.Revision).Substring(1).Insert(3,'.')

        # Check if the first digit after the dot is a 0 and remove it if so
        if ($CurrentDriverVersion -match '\.(0\d)') {
            $CurrentDriverVersion = $CurrentDriverVersion -replace '\.0(\d)', '.$1'
        }

        Write-Verbose "Current version: $CurrentDriverVersion" -Verbose
        return $CurrentDriverVersion
    }
    catch {
        Write-Verbose "Unable to detect a compatible Nvidia device. Seems like its the first driver install or a clean install for you." -Verbose
        return "first driver install or a clean install"
    }
}

function Download-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$url,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    CheckInternetConnection

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

function get7Zip {
    # Get the latest 7-Zip, if not already installed
    $7zipinstalled = $false
    $7ZipPathKey = "HKLM:\SOFTWARE\7-Zip\"
    
    if (Test-Path $7ZipPathKey) {
        $7ZipPath = (Get-ItemProperty -Path $7ZipPathKey -Name Path).Path
        $7ZipExe = Join-Path -Path $7ZipPath -ChildPath "7z.exe"
        
        if (Test-Path -Path $7ZipExe -PathType Leaf) {
            $7zipinstalled = $true
            Write-Verbose "7-Zip is already installed at $7ZipExe" -Verbose
            return $7ZipExe
        }
    }
    if (($7zipinstalled) -eq $false) {
        CheckInternetConnection

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
                return "$tempNvidiaFolder\7zip\Files\7-Zip\7z.exe"
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

function NvidiaInstallConfig {
    # https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
    # Mobile = 2
    $HardwareType = (Get-CimInstance -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
    if ($HardwareType -eq 2) {
        Write-Verbose "$Env:ComputerName is a Laptop" -Verbose
        # "nodejs" needed for gfexperience and rtx stuff, "PPC" needed for usb-c, "Display.Optimus" needed for notebooks
        if ($disableUsbC) {
            $nvidiaConfig = "nodejs Display.Optimus Display.Driver NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
            return $nvidiaConfig
        } else {
            $nvidiaConfig = "nodejs Display.Optimus Display.Driver NVI2 PhysX PPC EULA.txt ListDevices.txt setup.cfg setup.exe"
            return $nvidiaConfig
        }
    } else {
        Write-Verbose "$Env:ComputerName is a Desktop" -Verbose
        if ($disableUsbC) {
            $nvidiaConfig = "nodejs Display.Driver NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
            return $nvidiaConfig
        } else {
            $nvidiaConfig = "nodejs Display.Driver NVI2 PhysX PPC EULA.txt ListDevices.txt setup.cfg setup.exe"
            return $nvidiaConfig
        }
    }
}

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

            $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop

            $raw | Select-String '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches|
            ForEach-Object { $_.Matches } |
            ForEach-Object { 
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
        $gpuDeviceID = Get-CimInstance -Query "SELECT DeviceID FROM Win32_PNPEntity WHERE DeviceID LIKE '%PCI\\VEN_10DE%' AND (PNPClass = 'Display' OR Name = '3D Video Controller')" -ErrorAction Stop | Where-Object { $_.DeviceID -match 'DEV_(\w{4}).*SUBSYS_(\w{8})' } | Select-Object -First 1 -ExpandProperty DeviceID

        # Extract the device ID part
        if ($gpuDeviceID -match 'DEV_(\w{4}).*SUBSYS_(\w{8})') {
            $deviceIdPart1 = $Matches[1]
            $gpuDeviceID = $deviceIdPart1
        }

        if ($null -ne $gpuDeviceID) {
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

        CheckInternetConnection

        $Parameters = @{
        Uri = "https://gfwsl.geforce.com/nvidia_web_services/controller.gfeclientcontent.NG.php/com.nvidia.services.GFEClientContent_NG.getDispDrvrByDevid/%7B%22dIDa%22:%5B%22" + $gpuDeviceID +  "_0_0_0%22%5D,%22osC%22:%2210.0%22,%22osB%22:%22" + $osVersionBuild + "%22,%22is6%22:%221%22,%22lg%22:%221033%22,%22iLp%22:%220%22,%22prvMd%22:%220%22,%22gcV%22:%220%22,%22gIsB%22:%220%22,%22dch%22:%220%22,%22upCRD%22:%220%22,%22isCRD%22:%220%22%7D"
        UseBasicParsing = $true
        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        TimeoutSec = "60"
        ContentType = "application/json; charset=utf-8"
        Method = "GET"
        DisableKeepAlive = $true
        }
        $Data = Invoke-RestMethod @Parameters -ErrorAction Stop
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
        $CurrentDriverVersion = nvidiaCheckCurrentDriverVersion
        if ($CurrentDriverVersion -ne "first driver install or a clean install" -and $CurrentDriverVersion -eq $LatestVersion) {
            Write-Host ""
            Write-Verbose "Seems like you already have the latest nvidia driver installed.`nDo you still want to continue?" -Verbose
            $confirmation = Read-Host "(Y/N) Default is no"
            if ($confirmation -eq 'n' -or $confirmation -eq 'N') {
                cleanUp
                Write-Host "Bye Bye (-;"
                Write-Host "Press any key to exit..."
                $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                exit
            }
        }

        Write-Verbose "Downloading now the latest nvidia driver" -Verbose

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
$isNormalBoot = $checkBootMode -like "*Normal boot*"
$isFailSafeBoot = $checkBootMode -like "*Fail-safe*"

if ($isNormalBoot) {
    Write-Verbose "We are in a normal boot environment" -Verbose
    if ((-not (Test-Path 'HKLM:\Software\RebootDummyKey'))) {
        # Download and extract the nvidia driver first, if successfull we will start cleaning the current driver with DDU
        if (Test-Path -Path $tempNvidiaFolder) {
            Remove-item "$tempNvidiaFolder" -Recurse -Force
        }
        if (-Not (Test-Path -Path $tempNvidiaFolder)) {
            New-Item -Path $tempNvidiaFolder -ItemType Directory -Force | Out-Null
        }
        downloadNvidiaDriver

        $7zipPath = get7Zip

        if (-not(Test-Path -Path "$PSScriptRoot\DDU\*\Display Driver Uninstaller.exe" -PathType Leaf)) {
            Write-Verbose "Downloading DDU Driver Uninstaller" -Verbose
            Download-File -url "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.8.4.exe" -Destination "$env:Temp\DDU.exe"
            if (Test-Path -Path "$env:Temp\DDU.exe" -PathType Leaf) {
                & $7zipPath x "$env:Temp\DDU.exe" -o"$PSScriptRoot\DDU" -y
                Remove-Item -Path "$env:Temp\DDU.exe" -Force
            }
        }

        if ($enableNvidiaProfileInspector) {
            if (-not(Test-Path -Path "$PSScriptRoot\nvidiaProfileInspector\nvidiaProfileInspector.exe" -PathType Leaf)) {
                Download-GithubRelease -Repository "Orbmu2k/nvidiaProfileInspector" -FilePattern "*2.4.0.4*zip" -DestinationPath "$PSScriptRoot\nvidiaProfileInspector" -ExpectedHash "9DC8F944DC55C0ECA9BB939B1C756A093F8250B6D9DB76319BF27EF5FBE4CB83"
            }
        }

        $nvidiaConfig = NvidiaInstallConfig

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
            $nvidiaConfig,
            # Specifies a destination directory where files are to be extracted
            "-o`"$tempNvidiaFolder\NVidia`""
        )
        $Parameters = @{
            FilePath     = "$7zipPath"
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

        Write-Host ""
        Write-Verbose "`We will restart now your system in safe mode and clean your nvidia driver with DDU.`nDo you want to continue?" -Verbose
        $confirmation = Read-Host "(Y/N) Default is no"
        if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
            DisableAutoDriverUpdate
            # Create a runonce key in the registry to run the script automatically when you restart in safe mode.
            # By default, these keys are ignored when the computer is started in Safe Mode. The value name of RunOnce keys can be prefixed with an asterisk (*) to force the program to run even in Safe mode.
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force -Name "*RebootSafeMode*" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            # Reboot to safe mode
            Start-Process "$env:SystemRoot\System32\cmd.exe"-ArgumentList '/s,/c,bcdedit.exe /set {current} safeboot minimal & bcdedit.exe /deletevalue {current} safebootalternateshell & shutdown.exe -r -t 00 -f' -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue
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

if ($isFailSafeBoot) {
    Write-Verbose "We are in a safe boot environment" -Verbose
    # Driver uninstall with DDU, only if the system is in safe boot
    if ((-not (Test-Path 'HKLM:\Software\RebootDummyKey'))) {
        Write-Verbose "DDU Driver Uninstaller is now running, please wait..." -Verbose
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$PSScriptRoot\DDU\*\Display Driver Uninstaller.exe" -ArgumentList {"-silent", "-cleannvidia", "-RemovePhysx", "-RemoveGFE", "-RemoveNVBROADCAST", "-RemoveNVCP", "-NoRestorePoint"} -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        # Create a dummy registry key needed to continue the script after a reboot.
        New-Item 'HKLM:\Software\RebootDummyKey' -Force
        # Create a runonce key in the registry to run the script automatically after rebooting to normal boot.
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Force -Name "RebootNormalMode" -PropertyType "String" -Value "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        # Reboot to normal mode
        Start-Sleep -Seconds 3
        Start-Process "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/s,/c,bcdedit /deletevalue {current} safeboot & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb "RunAs" -WindowStyle Hidden -ErrorAction SilentlyContinue
        exit
    }
}

if ($isNormalBoot) {
    # Download and install nvidia driver
    if ((Test-Path 'HKLM:\Software\RebootDummyKey')) {
        Write-Verbose "Starting Nvidia install script" -Verbose
        Remove-Item -Path "HKLM:\Software\RebootDummyKey" -Force

        # Installing drivers
        Write-Verbose "Installing now the cleaned nvidia driver..." -Verbose
        Start-Sleep -Seconds 3
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
            Write-Verbose "Disabling USB-C" -Verbose
            # Define the friendly name of the device you want to disable
            $friendlyName = "NVIDIA USB 3.10 eXtensible-Hostcontroller – 1.10 (Microsoft)"

            # Retrieve the device and disable it
            Get-PnpDevice | Where-Object { $_.FriendlyName -eq $friendlyName } | ForEach-Object {
                Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false
            }
        }

        if ($enableNvidiaProfileInspector) {
            # Install nvidiaprofileinspector profile
            Write-Verbose "Install nvidiaprofileinspector profile" -Verbose
            $argument = '-silent'
            # If the path contains spaces or special characters, it should be wrapped in double quotes
            $escapedPath = "`"$NvidiaProfileInspectorProfile`""
            # Combine the escaped path and other arguments into the ArgumentList array
            $argumentList = "$escapedPath $argument"
            Start-Process -FilePath "$PSScriptRoot\nvidiaProfileInspector\nvidiaProfileInspector.exe" -ArgumentList $argumentList -Verb "RunAs" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
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
        Write-Host ""
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
