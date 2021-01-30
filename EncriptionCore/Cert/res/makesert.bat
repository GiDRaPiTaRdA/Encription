cd C:\Program Files (x86)\Windows Kits\8.1\bin\x64
set /p certName="Enter certificate name: "
set /p months="Enter trial in months: "


makecert ^
-r ^
-pe ^
-n "CN=%certName%" ^
-sky signature ^
-cy authority ^
-m %months% ^
-ss My C:\Users\Admin\Desktop\%certName%.cer ^
-sv My C:\Users\Admin\Desktop\%certName%.pvk

Pause