@echo off
cls

::enable powershell scripts
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command set-executionpolicy Unrestricted -force
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command set-executionpolicy RemoteSigned -force

::firewall
REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpsSvc\" /v Start /t REG_DWORD /d 2 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
netsh advfirewall set allprofiles state on
netsh firewall set opmode mode = enable
netsh firewall set opmode enable
netsh advfirewall set  currentprofile state on
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-NetFirewallProfile -All -Enabled True

::windows security center
REG add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v Start /t REG_DWORD /d 2 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Type DWord -Value 1"

::security center service
net start wscsvc /y 
REG add "HKLM\SYSTEM\CurrentControlSet\services\wscsvc" /v Start /t REG_DWORD /d 2 /f

::windows updates service
net start wuauserv /y
sc config wuauserv start = enabled

::windows defender realtime protection
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring 0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -Enabled True"

::windows defender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "2" /f
sc start WinDefend
sc config WinDefend start= enabled
sc start WinDefend

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $false
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableDefender" /t REG_DWORD /d "0" /f
:: powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat"
:: powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe"
:: powershell.exe -command "Set-MpPreference -PUAProtection disable"

Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f > Nul
:: Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f > Nul
:: Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "0" /f > Nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f  > Nul
:: reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "0" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "0"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "0" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
:: reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "1" /f

:: schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Enable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Enable

net start SystemEventsBroker /y
net start MpsSvc /y
net start SecurityHealthService /y
net start Wecsvc /y
net start WerSvc /y
Echo "security features Enabled"
pause