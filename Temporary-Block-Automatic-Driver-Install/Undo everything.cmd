@echo off & mode con cols=85 lines=12 & Color 1F & Title Undo everything
::——————————————————————————————————————————————————————————————————————————————————————————
(Fsutil Dirty Query %SystemDrive%>Nul)||(PowerShell start """%~f0""" -verb RunAs & Exit /B)
cd /d "%~dp0"
::——————————————————————————————————————————————————————————————————————————————————————————
wmic cpu get AddressWidth /value|find "32">nul&& set (bit)=(32)||set (bit)=(64)
if %(bit)%==(64) (set "nsudovar=.\bin\NSudoCx64.exe") else (set "nsudovar=.\bin\NSudoc.exe")
::=====================================================================================
::=====================================================================================
:: 以下指令來自 【Sledgehammer 2.6.0】
cls
set s32=%systemroot%\System32
::::::::::::::::::::::::::::::::::
::restore rempl folder permissions and delete rempl folder
takeown /f "%ProgramFiles%\rempl" /a >nul 2>&1
icacls "%ProgramFiles%\rempl" /reset >nul 2>&1
::restore rempl file permissions
for %%? in ("%ProgramFiles%\rempl\*") do (
takeown /f "%%?" /a >nul 2>&1
icacls "%%?" /q /c /reset >nul 2>&1
rem icacls "%%?" /setowner *S-1-5-18 >nul 2>&1
)
del "%ProgramFiles%\rempl\*.*" /f /q >nul 2>&1
rmdir "%ProgramFiles%\rempl" /s /q >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore Language Components Installer tasks to defaults
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*") do schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\%%~nx?" /enable >nul 2>&1
schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /disable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /setowner *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore Windows Update tasks to defaults
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*") do schtasks /change /tn "Microsoft\Windows\WindowsUpdate\%%~nx?" /enable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /setowner *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore default permissions to Update Hijacker files disabled by script
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll
::If "s32list" files were renamed by script, restore original file names
for %%# in (%s32list%) do (
ren "%s32%\%%#"-backup "%%#" >nul 2>&1
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q >nul 2>&1
)
::Now restore default permissions for Update Hijacker files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a >nul 2>&1
icacls "%s32%\%%#" /reset >nul 2>&1
icacls "%s32%\%%#" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
)
::restore Update Assistant folder permissions, then delete
takeown /f "%systemroot%\UpdateAssistant" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /reset >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %systemroot%\UpdateAssistant\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistant /s /q >nul 2>&1
takeown /f "%systemroot%\UpdateAssistantV2" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /reset >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %systemroot%\UpdateAssistantV2\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistantV2 /s /q >nul 2>&1
takeown /f "%systemdrive%\Windows10Upgrade" /a >nul 2>&1
icacls "%systemdrive%\Windows10Upgrade" /reset >nul 2>&1
icacls "%systemdrive%\Windows10Upgrade" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %SystemDrive%\Windows10Upgrade\*.* /f /q >nul 2>&1
rmdir %SystemDrive%\Windows10Upgrade /s /q >nul 2>&1
:: -------------------------------------------------
:: 以上指令來自 【Sledgehammer】。
::=====================================================================================
:: Delete and undo those by Matthew Wai and Me.

takeown /f "%SystemDrive%\Program Files\Microsoft Update Health Tools" /a >nul 2>&1
icacls "%SystemDrive%\Program Files\Microsoft Update Health Tools" /reset >nul 2>&1
icacls "%SystemDrive%\Program Files\Microsoft Update Health Tools" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %SystemDrive%\Program Files\Microsoft Update Health Tools\*.* /f /q >nul 2>&1
rmdir "%SystemDrive%\Program Files\Microsoft Update Health Tools" /s /q >nul 2>&1

Set "[NSudo]=%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E"

%[NSudo]% SC config "WaaSMedicSvc" start=demand
%[NSudo]% Schtasks /Change /Enable /Tn "Microsoft\Windows\WaaSMedic\PerformRemediation"

%[NSudo]% SC config "DsmSvc" start=demand
%[NSudo]% Schtasks /Change /Enable /Tn "Microsoft\Windows\Device Setup\Metadata Refresh"

::Enable Check for Updates Button in Windows Update Settings.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /f

::Enable Automatic Updates if you disabled it by wumt.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f

::Enable Windows Update automatic restart.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /f

::Enable Windows Auto Update.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f

Cls
wmic cpu get AddressWidth /value|find "32">nul&&set Name=bin\NSudoC.exe||set Name=bin\NSudoCx64.exe
Set "Run_commands="%Name%" -ShowWindowMode:Hide -Wait -U:T -P:E CMD /C"
Set "Key=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
%Run_commands% (REG ADD "%Key%" /V "Default" /T REG_DWORD /D 1 /F)
%Run_commands% (REG ADD "%Key%" /V "Ethernet" /T REG_DWORD /D 1 /F)
%Run_commands% (REG ADD "%Key%" /V "WiFi" /T REG_DWORD /D 1 /F)
::=====================================================================================

exit
