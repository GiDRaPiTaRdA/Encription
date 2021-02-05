cd C:\Program Files (x86)\Windows Kits\8.1\bin\x64
set /p certName="Enter certificate name: "
set /p months="Enter trial in months: "
set /p password="Enter password: "
set pass=%~dp0Certificates
md %pass%

makecert.exe ^
-n "CN=%certName%" ^
-r ^
-pe ^
-a sha1 ^
-m %months% ^
-sky exchange ^
-len 4096 ^
-cy authority ^
-sv %pass%\%certName%.pvk ^
%pass%\%certName%.cer

pvk2pfx.exe ^
-pvk %pass%\%certName%.pvk ^
-spc %pass%\%certName%.cer ^
-pfx %pass%\%certName%.pfx ^
-po %password%

pause

