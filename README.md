# Luna Ungrabber

![GitHub](https://img.shields.io/github/license/lululepu/LunaDeobfV2)
![Python](https://img.shields.io/badge/Python-3.x-blue)

Decrypt and analyze a Luna Ungrabber executable.

Thanks to extremecoders-re for pyinstxtractor.

You can now use the ungrabber website, it's free and easy to use. It works with BlankGrabber, CrealGrabber, LunaGrabber, PySilon, BCStealer, CStealer, and much more: [https://lululepu.fr](https://lululepu.fr).

## About

This Python script is designed to decrypt and analyze Luna Grabber executables. It extracts and decrypts the contents, deobfuscates the code, and identifies potential Discord webhooks used by the executable.

## Features

- Decrypt Luna Grabber executables
- Deobfuscate code
- Identify Discord webhooks
- Test identified webhooks

## Requirements

- Python 3.x
- Additional Python libraries (install using `pip install`):
  - pystyle
  - crypto
  - httpx

## Installation

```bash
git clone https://github.com/lululepu/LunaDeobfV2
cd LunaDeobfV2
py main.py
```

## Usage

The script operates by decompiling and deobfuscating various layers of a Luna Grabber executable, ultimately extracting any embedded Discord webhook URLs. Below is a brief overview of the key components and functions:

### Key Components

- **get_pyc_vers_header**: Determines the appropriate Python version header for the extracted executable.
- **Extract**: Extracts the content of the executable for analysis.
- **Compiled_Deobf**: Handles deobfuscation of compiled (PYC) code.
- **Plain_Deobf**: Deobfuscates plain (non-compiled) obfuscated code.
- **Extract_Config**: Extracts and returns the Discord webhook URL from the deobfuscated code.

### Deobfuscation Layers

The script uses multiple functions to handle different layers of obfuscation:
- **Layer_1_PYC**: Deobfuscates Layer 1 of compiled obfuscation.
- **Layer_2_PYC**: Deobfuscates Layer 2 of compiled obfuscation.
- **Layer_1_Plain**: Deobfuscates Layer 1 of plain obfuscation.
- **Layer_2_Plain**: Deobfuscates Layer 2 of plain obfuscation.
- **Layer_3_Plain**: Deobfuscates Layer 3 of plain obfuscation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
