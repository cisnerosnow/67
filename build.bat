@echo off
REM Build script para crear el ejecutable con PyInstaller

echo Instalando PyInstaller...
pip install --upgrade pyinstaller

echo.
echo Limpiando builds anteriores...
rmdir /s /q build dist __pycache__ 2>nul

echo.
echo Creando ejecutable...
pyinstaller --onefile --windowed --icon=logo.png --name="67" --clean 67.py

echo.
echo Build completado!
echo El ejecutable se encuentra en: dist\67.exe
pause
