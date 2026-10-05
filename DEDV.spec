# PyInstaller spec for DEDV. Run via build.bat (or: pyinstaller DEDV.spec).
# Output: dist/DEDV/DEDV.exe (one-folder build: faster startup, simpler installer updates).

a = Analysis(
    ["dedv/main.py"],
    # dedv/ for the app's flat imports; encryption/ because its modules import each other flatly.
    pathex=["dedv", "encryption"],
    datas=[
        # Add bundled resources here, e.g. ("dedv/resources", "resources")
    ],
    hiddenimports=["aes"],   # loaded via sys.path in encryption_service.py
    excludes=["tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DEDV",
    console=False,           # windowed app
    # icon="dedv/resources/icons/dedv.ico",   # uncomment once an .ico exists
)
coll = COLLECT(exe, a.binaries, a.datas, name="DEDV")
