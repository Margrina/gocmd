#!/bin/sh
# gocmd installer for Termux (Android), iSH (iPhone) and Linux.
#   curl -fsSL https://raw.githubusercontent.com/Margrina/gocmd/main/install.sh | sh
# Installs python3 + cryptography + git with the system package manager, downloads gocmd
# into ~/gocmd (or $GOCMD_DIR) and makes `gocmd` a command.
set -e
REPO="https://github.com/Margrina/gocmd"
DIR="${GOCMD_DIR:-$HOME/gocmd}"
echo "=== gocmd setup ==="

if [ -n "$TERMUX_VERSION" ] || echo "${PREFIX:-}" | grep -q com.termux; then
    echo "Termux detected."
    pkg update -y
    pkg install -y python python-cryptography git
elif [ -e /proc/ish ] || command -v apk >/dev/null 2>&1; then
    echo "iSH / Alpine detected (this can take a few minutes on iSH)."
    apk update
    apk add python3 py3-cryptography git
elif command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    $SUDO apt-get update
    $SUDO apt-get install -y python3 python3-cryptography python3-psutil git
else
    echo "Please install python3, the Python 'cryptography' package and git, then run this again."
    exit 1
fi

if [ -d "$DIR/.git" ]; then
    git -C "$DIR" pull -q --ff-only
else
    git clone -q --depth 1 "$REPO" "$DIR"
fi
cd "$DIR"
python3 gocmd.py --install
echo
echo "All set. Create a channel:  gocmd -u NAME --new"
echo "          Join a channel:   gocmd -u NAME -o CODE"
