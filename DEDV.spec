# PyInstaller spec for DEDV. Run via build.bat (or: pyinstaller DEDV.spec).
# Output: dist/DEDV/DEDV.exe (one-folder build: faster startup, simpler installer updates).

from PyInstaller.utils.hooks import collect_submodules

# The model pickle imports sklearn classes by name at load time (no static import to follow),
# so the sklearn packages it uses are collected explicitly.
ML_HIDDEN = ["dedv_ml.pipeline"]
for pkg in ("sklearn.compose", "sklearn.ensemble", "sklearn.tree", "sklearn.impute",
            "sklearn.preprocessing", "sklearn.pipeline", "sklearn.utils"):
    ML_HIDDEN += collect_submodules(pkg)

a = Analysis(
    ["dedv/main.py"],
    # dedv/ for the app's flat imports; encryption/ because its modules import each other flatly.
    pathex=["dedv", "encryption"],
    datas=[
        # Add bundled resources here, e.g. ("dedv/resources", "resources")
        ("model/final_model.joblib", "model"),   # read by paths.model_path() via sys._MEIPASS
        ("docs/DEVELOPER_INSTRUCTIONS.md", "docs"),   # shown on the Developer page (paths.docs_dir())
        # NOTE: no key material is ever bundled; the DEDV key is created at runtime in %LOCALAPPDATA%.
    ],
    hiddenimports=["aes", "chacha", "mlkem", "rsa"] + ML_HIDDEN,   # encryption/*.py, flat imports via sys.path
    excludes=["tkinter", "xgboost", "matplotlib", "IPython", "pytest"],  # not used at runtime
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
