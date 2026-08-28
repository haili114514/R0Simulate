@echo off
copy /y "%~dp0R0Simulate.sys" "%SystemRoot%\System32\drivers\"
copy /y "%~dp0R0Simulates.dll" "%SystemRoot%\System32\"
copy /y "%~dp0R0Simulates_msvc.dll" "%SystemRoot%\System32\"
setx /M PATH "%PATH%;C:\Windows\System32"
sc create R0Simulate binPath= "%SystemRoot%\System32\drivers\R0Simulate.sys" type= kernel start= system
sc start R0Simulate
pause