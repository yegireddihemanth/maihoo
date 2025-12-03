# OCR Dependencies Installation Guide

## Required Tools for Education Document Validation

### 1. Poppler (PDF to Image Conversion)
Poppler is required for `pdf2image` to convert PDF pages to images for OCR processing.

### 2. Tesseract (OCR Engine)
Tesseract performs optical character recognition on images and scanned PDFs.

## Installation

### macOS (using Homebrew)
```bash
# Install both tools
brew install poppler tesseract

# Optional: Install additional language support
brew install tesseract-lang
```

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install poppler-utils tesseract-ocr
```

### Windows
1. **Poppler:**
   - Download from: https://github.com/oschwartz10612/poppler-windows/releases/
   - Extract to `C:\Program Files\poppler`
   - Add `C:\Program Files\poppler\Library\bin` to PATH

2. **Tesseract:**
   - Download installer from: https://github.com/UB-Mannheim/tesseract/wiki
   - Run installer
   - Add installation directory to PATH

## Verify Installation
```bash
# Check Poppler
pdfinfo -v

# Check Tesseract
tesseract --version
```

## Alternative: Use Text-Based PDFs
If you cannot install poppler immediately, ensure education documents are:
- Text-based PDFs (not scanned images)
- Or upload as JPG/PNG images instead

The system will automatically try direct PDF text extraction first before attempting OCR.

## Current Status (macOS)
✅ **Poppler:** Installed (version 25.12.0)
✅ **Tesseract:** Installed (version 5.5.1)

Run this to verify on your system:
```bash
which pdfinfo && pdfinfo -v
which tesseract && tesseract --version
```

## Python Packages
Ensure these are installed in your Python environment:
```bash
pip install pdf2image pytesseract Pillow
```
