#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

VENV=.build-venv
NAME=mft-evilhunter

echo "[*] MFT-EvilHunter - Linux build"
echo

command -v python3 >/dev/null 2>&1 || {
    echo "[-] python3 not found. Install Python 3.9+ and try again." >&2
    exit 1
}

python3 - <<'PY' || { echo "[-] Python 3.9+ required" >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY

if [ ! -d "$VENV" ]; then
    echo "[*] Creating build virtualenv in $VENV"
    python3 -m venv "$VENV"
fi

PY="$VENV/bin/python"

echo "[*] Installing build dependencies"
"$PY" -m pip install --upgrade pip wheel --quiet
"$PY" -m pip install -r requirements.txt pyinstaller --quiet

echo "[*] Cleaning previous build"
rm -rf build dist "${NAME}.spec"

echo "[*] Building (this takes a few minutes)"

"$PY" -m PyInstaller \
    --onefile \
    --windowed \
    --name "$NAME" \
    --add-data "mft_evilhunter/rules/default.json:mft_evilhunter/rules" \
    --add-data "mft_evilhunter/gui/assets:mft_evilhunter/gui/assets" \
    --collect-submodules mft_evilhunter \
    --exclude-module tkinter \
    --exclude-module matplotlib \
    --exclude-module numpy \
    --exclude-module PIL \
    --exclude-module pytest \
    --noconfirm \
    mft-evilhunter.py

[ -f "dist/$NAME" ] || { echo "[-] expected dist/$NAME was not produced" >&2; exit 1; }
chmod +x "dist/$NAME"

echo
echo "[+] Build complete: dist/$NAME"
echo "[+] Size: $(du -h "dist/$NAME" | cut -f1)"
echo
