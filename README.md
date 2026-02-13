# Comparador de Archivos

Herramienta de análisis y comparación de archivos que detecta diferencias a nivel de byte, encoding, BOM, line endings y caracteres ocultos.

## Características

- **Detección de encoding**: Identifica la codificación de archivos con nivel de confianza
- **BOM detection**: Detecta Byte Order Mark (UTF-8, UTF-16, UTF-32)
- **Line endings**: Analiza finales de línea (CRLF, LF, CR) y detecta mezclas
- **Caracteres ocultos**: Encuentra caracteres no imprimibles e invisibles
- **Homoglifos**: Detecta caracteres Unicode que parecen ASCII pero no lo son
- **Hashes**: Calcula MD5, SHA-1 y SHA-256 para verificar integridad
- **Diferencias byte a byte**: Muestra la primera diferencia y distribución de bytes

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

```bash
python 67.py
```

1. Selecciona ambos archivos usando los botones "Examinar..."
2. Haz clic en "Comparar"
3. Revisa el análisis detallado en el panel de resultados

## Requisitos

- Python 3.8+
- Tkinter (incluido con Python)
- chardet

## Crear ejecutable (.exe)

Para crear un ejecutable independiente en Windows:

```bash
build.bat
```

O manualmente con PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=logo.png --name="ComparadorArchivos" 67.py
```

El ejecutable se generará en `dist\ComparadorArchivos.exe`

## Screenshot

La interfaz muestra:
- **Información General**: Nombre, tamaño, número de líneas
- **Encoding**: Codificación detectada con nivel de confianza
- **BOM**: Byte Order Mark y primeros bytes en hexadecimal
- **Line Endings**: Conteo de CRLF, LF, CR
- **Hashes**: MD5, SHA-1, SHA-256
- **Caracteres Ocultos**: Lista de caracteres no imprimibles
- **Homoglifos**: Caracteres Unicode similares a ASCII
- **Diferencias**: Distribución de bytes y primera diferencia encontrada
