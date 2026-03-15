#!/usr/bin/env python3
"""
Build script for unp7m.
Creates a standalone executable for the current platform.

Requirements:
    pip install pyinstaller
    pip install -r requirements.txt

On macOS, also install:
    pip install pyobjc-core pyobjc-framework-Cocoa
"""

import platform
import subprocess
import sys

SYSTEM = platform.system()


def build():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "unp7m",
        "--windowed",
        "-y",
    ]

    # ca-italiane.pem bundling (path separator differs per OS)
    if SYSTEM == "Windows":
        cmd += ["--add-data", "ca-italiane.pem;."]
    else:
        cmd += ["--add-data", "ca-italiane.pem:."]

    # macOS: include PyObjC for Apple Events
    if SYSTEM == "Darwin":
        cmd += [
            "--hidden-import=Foundation",
            "--hidden-import=AppKit",
            "--hidden-import=PyObjCTools",
            "--hidden-import=PyObjCTools.AppHelper",
            "--hidden-import=objc",
        ]

    # Windows: single file .exe, no console
    if SYSTEM == "Windows":
        cmd += ["--onefile"]

    cmd.append("unp7m.py")

    print(f"Building for {SYSTEM}...")
    print(f"Command: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    if SYSTEM == "Windows":
        print("\nDone! Executable: dist/unp7m.exe")
        print("To associate .p7m files: right-click a .p7m -> Open with -> Choose another app -> Browse to dist/unp7m.exe")
    elif SYSTEM == "Darwin":
        # Add CFBundleDocumentTypes to Info.plist
        plist = "dist/unp7m.app/Contents/Info.plist"
        cmds = [
            f"Add :CFBundleDocumentTypes array",
            f"Add :CFBundleDocumentTypes:0 dict",
            f"Add :CFBundleDocumentTypes:0:CFBundleTypeName string 'P7M Signed Document'",
            f"Add :CFBundleDocumentTypes:0:CFBundleTypeRole string 'Viewer'",
            f"Add :CFBundleDocumentTypes:0:CFBundleTypeExtensions array",
            f"Add :CFBundleDocumentTypes:0:CFBundleTypeExtensions:0 string 'p7m'",
        ]
        for c in cmds:
            subprocess.run(["/usr/libexec/PlistBuddy", "-c", c, plist],
                           capture_output=True)

        print("\nDone! App bundle: dist/unp7m.app")
        print("To associate .p7m files: right-click a .p7m -> Open With -> Other -> select dist/unp7m.app")
    else:
        print(f"\nDone! Executable: dist/unp7m")


if __name__ == "__main__":
    build()
