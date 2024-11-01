Automatically clean the current driver in Safe Boot, download the latest nvidia driver, remove the telemetry and finally install the driver. This is the cleanest and easiest way to install a nvidia driver.

There are a few more extras, you just need to edit them in the script.

# $True/$False Add a nvidia profile inspector profile
$enableNvidiaProfileInspector = $true

$NvidiaProfileInspectorProfile = "NvidiaBaseProfile.nip"

# $True/$False Disable GPU USB-C port
$disableUsbC = $true

# $True/$False Disable HDAudioSleepTimer
$disableHdAudioSleepTimer = $true

# $True/$False Disable HDCP - (required for DRM content)
$disableHdcp = $true

# $True/$False Disable nvidia tray icon
$disableNvidiaTrayIcon = $true

# $True/$False disable nvidia telemetry and enable msi mode
$enableTweaksandDisableTelemetry = $true
