@echo off
rem Launches BandCap (it asks for admin rights itself).
where pyw >nul 2>&1 && (start "" pyw -3 "%~dp0bandcap.py" & exit /b)
start "" pythonw "%~dp0bandcap.py"
