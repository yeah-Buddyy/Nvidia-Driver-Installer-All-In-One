Automatically clean the current driver in Safe Boot, download the latest nvidia driver, remove the telemetry and finally install the driver. This is the cleanest way to install a nvidia driver.

There are a few more extras, you just need to edit them in the script.

# Display driver uninstaller path
$DDU = "$PSScriptRoot\DDU v18.0.7.7\Display Driver Uninstaller.exe"

# $True/$False Add a nvidia profile inspector profile
$enableNvidiaProfileInspector = $true

$NvidiaProfileInspector = "$PSScriptRoot\nvidiaProfileInspector2.4.0.4\nvidiaProfileInspector.exe"

$NvidiaProfileInspectorProfile = "$PSScriptRoot\nvidiaProfileInspector2.4.0.4\NvidiaBaseProfile.nip"

# $True/$False Disable GPU USB-C port
$disableUsbC = $true

$DevManView = "$PSScriptRoot\devmanview-x64\DevManView.exe"

# $True/$False Disable HDAudioSleepTimer
$disableHdAudioSleepTimer = $true

# $True/$False Disable HDCP - (required for DRM content)
$disableHdcp = $true

# $True/$False Disable nvidia tray icon
$disableNvidiaTrayIcon = $true

# $True/$False disable nvidia telemetry and enable tweaks
$enableTweaksandDisableTelemetry = $true

# WARNING !!!
It is possible that your anti-virus software will detect this as a virus. The reason for this is that this repository contains some executable files, but these are all false positives. If you are unsure, please download them from the original sites and replace them.

https://www.wagnardsoft.com/display-driver-uninstaller-DDU-

https://www.nirsoft.net/utils/device_manager_view.html

https://github.com/Orbmu2k/nvidiaProfileInspector

https://github.com/M2TeamArchived/NSudo/


