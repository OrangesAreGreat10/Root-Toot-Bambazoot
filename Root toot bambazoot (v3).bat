echo off
cls
echo Run as Administartor?
echo (Y/n)
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='Y' goto admin
if '%choice%'=='N' goto start2
if '%choice%'=='' goto admin



:admin

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
        
	echo UAC.ShellExecute "C:\desktop\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
	echo UAC.ShellExecute "E:\desktop\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "F:\desktop\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "D:\desktop\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "C:\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
	echo UAC.ShellExecute "E:\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "F:\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "D:\Root toot bambazoot (v.3).bat", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
cls

:start2
Echo ----Root Toot bambazoot V.3 Recreated by Keenan McCray----
echo
ECHO 1. Disable Guest and Admin Status
ECHO 2. Rename Guest and Admin Accounts
ECHO 3. Disable Requirement for Ctrl+Alt+Del to logon
ECHO 4. Turns on Automatic Updates
ECHO 5. Set Account Policies
ECHO 6. Set Audit Policies
ECHO 7. UAC Consent Prompt Behavior
ECHO 8. Enable Smart Screen
echo 9. Disable print spooler
echo W. Turn on windows action center
echo U. Check for updates
ECHO B. Resets Windows Firewall to Default Settings
ECHO D. Block Microsoft Account Logon
echo P. Set user passwords      			(CyberPatriot123!)
echo S. Set services 
ECHO A. All of the above (Proceed with Caution)
ECHO C. Go Back
ECHO E. End
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto dgaas
if '%choice%'=='2' goto rgaaa
if '%choice%'=='3' goto lcad
if '%choice%'=='4' goto au
if '%choice%'=='5' goto ap
if '%choice%'=='6' goto aup
if '%choice%'=='7' goto uac
if '%choice%'=='8' goto ss
if '%choice%'=='9' goto ps
if '%choice%'=='U' goto cfup
if '%choice%'=='W' goto wac
if '%choice%'=='B' goto rfs
if '%choice%'=='D' goto bml
if '%choice%'=='F' goto ddls
if '%choice%'=='A' goto all
if '%choice%'=='C' goto goback
if '%choice%'=='P' goto passwd
if '%choice%'=='S' goto services
if '%choice%'=='E' goto end
ECHO "%choice%" is not available, try again
ECHO.
cls
goto start2




:passwd
echo -----------------------------------------------------------------------------------------------------
 echo Set Users Passwords? (Password is "CyberPatriot123!" It does NOT apply to the host user) [Y/N]?

set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='Y' goto passwdy
if '%choice%'=='N' goto start2
if '%choice%'=='' goto end

:passwdy 
echo. & echo Setting user passwords...

wmic useraccount get name/value | find /V /I "%username%" > %APPDATA%\userlist.txt

REM Get everything after the equals
for /F "tokens=2* delims==" %%U in (%APPDATA%\userlist.txt) do (
	REM So after further inspection, there is this weird line ending to WMIC output, so this loop removes the ending and just passes the username.
	for %%u in (%%~U) do (
		net user %%~u CyberPatriot123! >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordExpires=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordRequired=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordChangeable=TRUE >> nul 2>&1
	)
)
goto start2

:services
echo -----------------------------------------------------------------------------------------------------
REM Regardless, set these keys
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1

echo. & echo Remote Services Configured
echo --------------------------------------------------------------------------------
echo. & echo Configuring services

for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled >> nul 2>&1
	sc stop %%S >> nul 2>&1
)

for %%S in (eventlog,mpssvc) do (
	sc config %%S start= auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand >> nul 2>&1
)

echo. & echo Services configured.
echo --------------------------------------------------------------------------------
echo. & echo Configuring Remote Services



goto start2






:dgaas
net user guest /active:no
net user administrator /active:no
goto start2
:rgaaa
powershell Rename-LocalUser -Name "Guest" -NewName "Bodhi"
powershell Rename-LocalUser -Name "Administrator" -NewName "Adrian"
goto start2
:lcad
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DisableCAD  /t REG_DWORD /d 1 /f
goto start2
:au
wuauclt.exe /updatenow
goto start2
:ap
net accounts /lockoutthreshold:5
net accounts /MINPWLEN:14
net accounts /MINPWAGE:30
net accounts /MAXPWAGE:90
net accounts /UNIQUEPW:5
goto start2

:aup
echo Select your Audit Policy
ECHO 1. Win-10
ECHO 2. Server
set choice=
set /p choice=Type the number to load batch file. Listed in recommended order.
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto win-10aup
if '%choice%'=='2' goto win-serveraup
goto start2
:win-10aup
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
goto start2
:win-serveraup
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
goto start2
:uac
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin  /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
goto start2
:ss
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft /v SmartScreenForTrustedDownloadsEnabled /t REG_DWORD /d 1 /f
goto start2

:ps
net stop spooler
goto start2
:rfs
netsh advfirewall reset
goto start2
:bml
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser /t REG_DWORD /d 3 /f
goto start2
:ddls
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserSwitch /v Enabled /t REG_DWORD /d 1 /f
goto start2




:all
echo -----------------------------------------------------------------------------------------------------------------------------------------------------------------
echo Running entire script!!
echo -----------------------------------------------------------------------------------------------------------------------------------------------------------------

net user guest /active:no
net user administrator /active:no

powershell Rename-LocalUser -Name "Guest" -NewName "Gossip Grannies"
powershell Rename-LocalUser -Name "Administrator" -NewName "Coach Anthony"

REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DisableCAD  /t REG_DWORD /d 0 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 3 /f

net accounts /lockoutthreshold:5
net accounts /MINPWLEN:14
net accounts /MINPWAGE:30
net accounts /MAXPWAGE:90
net accounts /UNIQUEPW:5

echo Select your Audit Policies
ECHO 1. Win-10
ECHO 2. Server
set choice=
set /p choice=Type the number to load batch file. Listed in recommended order.
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto win-10ap-all
if '%choice%'=='2' goto :win-serverap-all

:win-10ap-all
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
goto regedit-all

:win-serverap-all
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
goto regedit-all


:regedit-all
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin  /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft /v SmartScreenForTrustedDownloadsEnabled /t REG_DWORD /d 1 /f

netsh advfirewall reset
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser /t REG_DWORD /d 3 /f


echo Stop print spooler?
ECHO Y
ECHO N
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='Y' goto allps
if '%choice%'=='N' goto cfup-all
if '%choice%'=='y' goto allps
if '%choice%'=='n' goto cfup-all

:allps
net stop spooler


rem passwords
echo. & echo Setting user passwords...       (Password is "CyberPatriot123!" It does NOT apply to the host user)

wmic useraccount get name/value | find /V /I "%username%" > %APPDATA%\userlist.txt

REM Get everything after the equals
for /F "tokens=2* delims==" %%U in (%APPDATA%\userlist.txt) do (
	REM So after further inspection, there is this weird line ending to WMIC output, so this loop removes the ending and just passes the username.
	for %%u in (%%~U) do (
		net user %%~u CyberPatriot123! >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordExpires=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordRequired=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordChangeable=TRUE >> nul 2>&1
	)
)

rem services
echo -----------------------------------------------------------------------------------------------------
REM Regardless, set these keys
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer /v EnableSmartScreen /t REG_DWORD /d 2 /f
REG ADD HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion /v EnableWebContentEvaluation /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft /v SmartScreenForTrustedDownloadsEnabled /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin  /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser /t REG_DWORD /d 3 /f
REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserSwitch /v Enabled /t REG_DWORD /d 1 /f

echo. & echo Remote Services Configured
echo --------------------------------------------------------------------------------
echo. & echo Configuring services

for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled >> nul 2>&1
	sc stop %%S >> nul 2>&1
)

for %%S in (eventlog,mpssvc) do (
	sc config %%S start= auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand >> nul 2>&1
)

echo. & echo Services configured.
echo --------------------------------------------------------------------------------
echo. & echo Configuring Remote Services





:rfs all
netsh advfirewall reset



:end
ECHO ____________________
  Hostname
Echo ____________________
 Echo Cyberpatriot quote Hall Of Fame
 echo "Just do it" Anthony Scubadiver
 echo "Cpat gave me stokholm sindrome" Harrison isachild
 echo "My teacher is from Mars and cant read english" Bodhi Wolfenstein
echo            .--._.--.
echo           ( O     O )
echo           /   . .   \
echo          .`._______.'.
echo         /(   frong   )\
echo       _/  \  \   /  /  \_
echo    .~   `  \  \ /  /  '   ~.
echo   {    -.   \  V  /   .-    }
echo _ _`.    \  |  |  |  /    .'_ _
echo >_       _} |  |  | {_       _<
echo /. - ~ ,_-'  .^.  `-_, ~ - .\
echo          '-'|/   \|`-`
pause
 
 
 
 
 
 
 
 
