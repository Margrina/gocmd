#!/usr/bin/env python3
"""Build dist/gocmd-<version>.msi: embedded Python + cryptography/psutil + the official gocmd.py.

    python installer/build_msi.py --wix PATH\\TO\\wix.exe [--cache DIR]

Needs internet the first time (python.org embeddable Python, PyPI wheels); later builds reuse
the cache. gocmd.py is copied byte-for-byte so the gocmd server accepts it as official.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_VERSION = "3.13.17"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-embed-amd64.zip"


def run(*cmd):
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wix", required=True, help="path to wix.exe (WiX Toolset 5)")
    ap.add_argument("--cache", default=os.path.join(ROOT, "build", "cache"))
    a = ap.parse_args()

    src = open(os.path.join(ROOT, "gocmd.py"), "rb").read()
    version = re.search(rb'^VERSION = "([\d.]+)"', src, re.M).group(1).decode()
    build = os.path.join(ROOT, "build", "payload")
    shutil.rmtree(build, ignore_errors=True)
    os.makedirs(a.cache, exist_ok=True)

    # 1) embeddable Python
    pyzip = os.path.join(a.cache, f"python-{PY_VERSION}-embed-amd64.zip")
    if not os.path.exists(pyzip):
        urllib.request.urlretrieve(PY_URL, pyzip)
    pydir = os.path.join(build, "python")
    zipfile.ZipFile(pyzip).extractall(pydir)
    pth = next(f for f in os.listdir(pydir) if f.endswith("._pth"))
    with open(os.path.join(pydir, pth), "a", encoding="ascii") as f:
        f.write("\nLib\\site-packages\n")

    # 2) libraries
    wheels = os.path.join(a.cache, "wheels")
    run(sys.executable, "-m", "pip", "download", "-q", "--only-binary=:all:", "--platform", "win_amd64",
        "--python-version", "3.13", "--implementation", "cp", "-d", wheels, "-r",
        os.path.join(ROOT, "requirements.txt"))
    run(sys.executable, "-m", "pip", "install", "-q", "--no-index", "--find-links", wheels, "--only-binary=:all:",
        "--platform", "win_amd64", "--python-version", "3.13", "--implementation", "cp",
        "--target", os.path.join(pydir, "Lib", "site-packages"), "-r", os.path.join(ROOT, "requirements.txt"))

    # 3) gocmd itself (byte-for-byte), config, launcher
    with open(os.path.join(build, "gocmd.py"), "wb") as f:
        f.write(src)
    for name in ("gocmd_config.json", "README.md"):
        shutil.copy2(os.path.join(ROOT, name), build)
    with open(os.path.join(build, "gocmd.bat"), "w", encoding="ascii", newline="") as f:
        f.write('@echo off\r\n"%~dp0python\\python.exe" "%~dp0gocmd.py" %*\r\n')
    open(os.path.join(build, ".gocmd_setup_done"), "w").close()     # PATH is set by the installer

    # 4) sanity check: the bundled Python runs gocmd with its libraries
    run(os.path.join(pydir, "python.exe"), "-c", "import cryptography, psutil")
    run(os.path.join(pydir, "python.exe"), os.path.join(build, "gocmd.py"), "--version")

    # 5) MSI
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    out = os.path.join(dist, f"gocmd-{version}.msi")
    run(a.wix, "build", os.path.join(ROOT, "installer", "gocmd.wxs"), "-d", f"Version={version}",
        "-bindpath", f"payload={build}", "-arch", "x64", "-o", out)
    for leftover in (out[:-4] + ".wixpdb",):
        if os.path.exists(leftover):
            os.remove(leftover)
    print(f"\nBuilt {out}  ({os.path.getsize(out) / 1048576:.1f} MB)")
    print("gocmd.py sha256:", hashlib.sha256(src).hexdigest())


if __name__ == "__main__":
    main()
