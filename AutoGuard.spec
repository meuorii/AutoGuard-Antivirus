# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-file Windows build for AutoGuard."""
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

project_root = Path(SPECPATH)
datas = [(str(project_root / "data" / "signatures.json"), "data")]
assets_dir = project_root / "assets"
if assets_dir.exists():
    for item in assets_dir.rglob("*"):
        if item.is_file(): datas.append((str(item), str(item.parent.relative_to(project_root))))
datas += collect_data_files("customtkinter")
hiddenimports = (
    collect_submodules("apscheduler")
    + collect_submodules("watchdog")
    + collect_submodules("customtkinter")
    + collect_submodules("winotify")
    + collect_submodules("pystray")
    + collect_submodules("PIL")
)

a = Analysis(
    [str(project_root / "main.py")], pathex=[str(project_root)], binaries=[], datas=datas,
    hiddenimports=hiddenimports, hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [], name="AutoGuard", debug=False,
    bootloader_ignore_signals=False, strip=False, upx=True, upx_exclude=[],
    runtime_tmpdir=None, console=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None,
    icon=str(project_root / "assets" / "autoguard.ico"),
    version=str(project_root / "version_info.txt"),
)
