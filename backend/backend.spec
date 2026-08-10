# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: офлайн-сборка бэкенда в папку dist/fstec-backend.

Запуск:
    cd backend
    pyinstaller backend.spec
"""
import os

BACKEND = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    ["run_server.py"],
    pathex=[BACKEND],
    binaries=[],
    datas=[],
    hiddenimports=[
        "uvicorn",
        "uvicorn.loops.auto",
        "uvicorn.loops.asyncio",
        "uvicorn.loops.uvloop",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.protocols.websockets.wsproto_impl",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "uvicorn.lifespan",
        "pdfminer.high_level",
        "pdfminer.pdfinterp",
        "pdfminer.converter",
        "pdfminer.image",
        "pdfminer.utils",
        "pdfminer.pdfpage",
        "pdfminer.pdftypes",
        "pdfminer.psparser",
        "pdfminer.pdffont",
        "pdfminer.pdfcolor",
        "pdfminer.cmapdb",
        "pdfminer.layout",
        "pdfminer.encodingdb",
        "pdfminer.arcreader",
        "pdfminer.pdfdocument",
        "pdfminer.pdfparser",
        "pdfminer.pdftoken",
        "pdfminer.settings",
        "pdfminer.runlength",
        "pdfminer.ccitt",
        "pdfminer.rle",
        "pdfminer.psexceptions",
        "pdfminer.pwps",
        "pdfminer.glyphlist",
        "pdfminer.latin_enc",
        "pydantic",
        "pydantic.deprecated",
        "pydantic_core",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="fstec-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name="fstec-backend",
)
