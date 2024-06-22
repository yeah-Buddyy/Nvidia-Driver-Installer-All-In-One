@echo off & Title Disabling hijackers & mode con cols=60 lines=16 & Color 1F & Goto (Start)
::——————————————————————————————————————————————————————————————————————————————————————————
Original script by pf100 @ MDL with special thanks to rpo and abbodi1406 @ MDL for code improvements.
Project page and source code:
https://forums.mydigitallife.net/threads/sledgehammer-windows-10-update-control.72203/
*******************************************************************
You may freely modify this script as you wish, I only request that you leave the credits and the
link to the original script.
*******************************************************************
WUMT is available here: https://forums.mydigitallife.net/threads/64939-Windows-Update-MiniTool
NSudo is available here: https://github.com/M2Team/NSudo/releases/tag/6.1
*******************************************************************
How it works: The script first checks if the OS is Windows 8.1 or older and if so
it notifies the user, then exits. Windows 10 only!
This script creates a smart Windows Defender Update task "WDU" that updates Windows
Defender every 6 hours if it's running and enabled, and doesn't update it if it's not
running and disabled, saving resources; auto-elevates, uninstalls and removes the
Windows 10 Update Assistant, disables everything in the %programfiles%\rempl folder, resets and
removes permissions from and disables these Update Hijackers:
EOSNotify.exe
WaaSMedic.exe
WaasMedicSvc.dll
WaaSMedicPS.dll
WaaSAssessment.dll
UsoClient.exe
SIHClient.exe
MusNotificationUx.exe
MusNotification.exe
osrss.dll
%ProgramFiles%\rempl
%systemroot%\UpdateAssistant
%systemroot%\UpdateAssistantV2
%systemdrive%\Windows10Upgrade
disables all WindowsUpdate tasks
::——————————————————————————————————————————————————————————————————————————————————————————
:(Start)
(Fsutil Dirty Query %SystemDrive%>Nul)||(PowerShell start """%~f0""" -verb RunAs & Exit /B)
cd /d "%~dp0"
::——————————————————————————————————————————————————————————————————————————————————————————
@echo off & cls
::Test for Windows versions below Windows 10 and if so inform user, then exit...
::Get Windows OS build number
for /f "tokens=2 delims==" %%a in ('wmic path Win32_OperatingSystem get BuildNumber /value') do (
  set /a WinBuild=%%a)
if %winbuild% LEQ 9600 (echo.&echo This is not Windows 10. Press a key to exit...& pause > nul & exit)
::——————————————————————————————————————————————————————————————————————————————————————————
wmic cpu get AddressWidth /value|find "32">nul&& set (bit)=(32)||set (bit)=(64)
if %(bit)%==(64) (set "nsudovar=.\bin\NSudoCx64.exe") else (set "nsudovar=.\bin\NSudoc.exe")
::——————————————————————————————————————————————————————————————————————————————————————————
echo. &echo. &echo.
echo.         Operations are in progress. Please wait.
::==========================================================================================
:: The following are extracted from Sledgehammer 2.6.0
:: ---------------------------------------------------
takeown /f "%systemroot%\UpdateAssistant" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /reset >nul 2>&1
del %systemroot%\UpdateAssistant\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistant /s /q >nul 2>&1
md "%systemroot%\UpdateAssistant" >nul 2>&1
attrib +s +h "%systemroot%\UpdateAssistant" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemroot%\UpdateAssistant /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
takeown /f "%systemroot%\UpdateAssistantV2" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /reset >nul 2>&1
del %systemroot%\UpdateAssistantV2\*.* /f /q >nul 2>&1
md "%systemroot%\UpdateAssistantV2" >nul 2>&1
attrib +s +h "%systemroot%\UpdateAssistantV2" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemroot%\UpdateAssistantV2 /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
takeown /f "%SystemDrive%\Windows10Upgrade" /a >nul 2>&1
icacls "%SystemDrive%\Windows10Upgrade" /reset >nul 2>&1
del %SystemDrive%\Windows10Upgrade\*.* /f /q >nul 2>&1
rmdir %SystemDrive%\Windows10Upgrade /s /q >nul 2>&1
md "%systemdrive%\Windows10Upgrade" >nul 2>&1
attrib +s +h %systemdrive%\Windows10Upgrade >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemdrive%\Windows10Upgrade /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
::Disable rempl
if not exist "%ProgramFiles%\rempl" goto norempl
takeown /f "%ProgramFiles%\rempl" /a >nul 2>&1
icacls "%ProgramFiles%\rempl" /reset >nul 2>&1
for %%? in ("%ProgramFiles%\rempl\*") do (
takeown /f "%%?" /a >nul 2>&1
icacls "%%?" /reset >nul 2>&1
)
del %ProgramFiles%\rempl\*.* /f /q >nul 2>&1
rmdir %ProgramFiles%\rempl /s /q >nul 2>&1
:norempl
::The rempl folder doesn't exist, so create it and lock it from system access.
md "%ProgramFiles%\rempl" >nul 2>&1
attrib +s +h "%ProgramFiles%\rempl" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" "%ProgramFiles%\rempl" /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
:: Disable all Language Components Installer tasks
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*") do schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\%%~nx?" /disable >nul 2>&1
::::::::::::::::::::::::::::
:: Disable and lock all Windows Update tasks.
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*") do schtasks /change /tn "Microsoft\Windows\WindowsUpdate\%%~nx?" /disable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
::Set list (s32list) of update hijacker files to be disabled, then disable everything in the list.
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll
set s32=%systemroot%\System32
::If "s32list" files were previously renamed by script, restore original file names
for %%# in (%s32list%) do (
ren "%s32%\%%#"-backup "%%#" >nul 2>&1
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q >nul 2>&1
)
::Lock files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a >nul 2>&1
icacls "%s32%\%%#" /reset >nul 2>&1
if exist "%s32%\%%#" %nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" "%s32%\%%#" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
)
::If files in "s32list" aren't locked for whatever reason, rename them.
for %%# in (%s32list%) do (
ren "%s32%\%%#" "%%#"-backup >nul 2>&1
if exist "%s32%\%%#"-backup del "%s32%\%%#" /f /q >nul 2>&1
)
:: -------------------------------------------------
:: The end of the stuff extracted from Sledgehammer.
::=====================================================================================
:: The following were added by Matthew Wai and Me.
Set "[NSudo]=%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E"

::Disable the task and service of "Windows Update Medic Service".
%[NSudo]% Schtasks /Change /Disable /Tn "Microsoft\Windows\WaaSMedic\PerformRemediation"
%[NSudo]% SC config "WaaSMedicSvc" start=disabled

::Disable the task and service of "Automatic Driver Download and Install".
%[NSudo]% Schtasks /Change /Disable /Tn "Microsoft\Windows\Device Setup\Metadata Refresh"
%[NSudo]% SC config "DsmSvc" start=disabled

::Disable Check for Updates Button in Windows Update Settings.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d 1 /f

::Disabling Windows Update automatic restart.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f

::Disabling Windows Auto Update.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f

:[Lock the "Microsoft Update Health Tools" folder]
takeown /f "%SystemDrive%\Program Files\Microsoft Update Health Tools" /a >nul 2>&1
icacls "%SystemDrive%\Program Files\Microsoft Update Health Tools" /reset >nul 2>&1
del "%SystemDrive%\Program Files\Microsoft Update Health Tools\*.*" /f /q >nul 2>&1
rmdir "%SystemDrive%\Program Files\Microsoft Update Health Tools" /s /q >nul 2>&1
md "%SystemDrive%\Program Files\Microsoft Update Health Tools" >nul 2>&1
attrib +s +h "%SystemDrive%\Program Files\Microsoft Update Health Tools" >nul 2>&1
%[NSudo]% "%systemroot%\System32\icacls.exe" "%SystemDrive%\Program Files\Microsoft Update Health Tools" /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1

wmic cpu get AddressWidth /value|find "32">nul&&set Name=bin\NSudoC.exe||set Name=bin\NSudoCx64.exe
Set "[Run]="%Name%" -ShowWindowMode:Hide -Wait -U:T"
Set "Key=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
%[Run]% REG ADD "%Key%" /V "Default" /T REG_DWORD /D 2 /F
%[Run]% REG ADD "%Key%" /V "Ethernet" /T REG_DWORD /D 2 /F
%[Run]% REG ADD "%Key%" /V "WiFi" /T REG_DWORD /D 2 /F

exit