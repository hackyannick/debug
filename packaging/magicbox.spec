# PyInstaller-Spezifikation für die Desktop-App:  pyinstaller --noconfirm --clean packaging/magicbox.spec
# Ergebnis: dist/MagicBox/ (Ordner-Variante – startet schneller und verträgt sich besser mit Qt WebEngine)
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 – von PyInstaller gesetzt
ICON = str(ROOT / "magicbox" / "assets" / ("magicbox.ico" if sys.platform == "win32" else "magicbox.png"))

# Daten und Module direkt aus dem Quellordner einsammeln – collect_data_files("magicbox") findet das Paket
# nur, wenn es installiert ist, und lässt sonst still Web-Oberfläche, YARA-Regeln und CSS weg.
PKG = ROOT / "magicbox"
datas = [(str(f), str(f.parent.relative_to(ROOT))) for f in PKG.rglob("*")
         if f.is_file() and f.suffix not in (".py", ".pyc") and "__pycache__" not in f.parts]
hiddenimports = [".".join(f.relative_to(ROOT).with_suffix("").parts).removesuffix(".__init__")
                 for f in PKG.rglob("*.py")]
datas += collect_data_files("oletools")
hiddenimports += collect_submodules("oletools")

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "numpy", "pytest", "IPython"],
    noarchive=False,
)
# --- Schlank halten: PyInstaller zieht sonst ALLE QML-Module von Qt mit (3D, Charts, Multimedia, …; ~500 MB).
# Die App braucht nur Qt WebEngine samt Abhängigkeiten (ermittelt per ldd) und die Plattform-Anbindung.
import re

QT_KEEP = {
    "Core", "Gui", "Widgets", "Network", "OpenGL", "OpenGLWidgets", "DBus", "PrintSupport", "Positioning",
    "Qml", "QmlMeta", "QmlModels", "QmlWorkerScript", "Quick", "QuickWidgets", "WebChannel",
    "WebEngineCore", "WebEngineWidgets", "Svg",
    "XcbQpa", "WaylandClient", "EglFSDeviceIntegration", "EglFsKmsSupport",  # Linux-Plattformen
}
QT_LIB = re.compile(r"(?:^|[/\\])(?:lib)?Qt6([A-Za-z0-9]+?)(?:\.so[.0-9]*|\.dll)$")
WEBENGINE_LOCALES = {"en-US.pak", "de.pak"}


def keep(dest: str) -> bool:
    d = dest.replace("\\", "/")
    m = QT_LIB.search(d)
    if m and m.group(1) not in QT_KEEP:
        return False
    if "/qml/" in d or d.startswith("PySide6/qml") or "/Qt/qml" in d:
        return False
    if "qtwebengine_locales/" in d and d.rsplit("/", 1)[-1] not in WEBENGINE_LOCALES:
        return False
    if "/translations/" in d and "qtwebengine_locales" not in d and not d.rsplit("/", 1)[-1].startswith(("qtbase_de", "qt_de")):
        return False
    return True


before = len(a.binaries) + len(a.datas)
a.binaries = [b for b in a.binaries if keep(b[0])]
a.datas = [x for x in a.datas if keep(x[0])]
print(f"magicbox.spec: {before - len(a.binaries) - len(a.datas)} Qt-Dateien ausgelassen")

pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MagicBox",
    console=False,  # Fensteranwendung ohne Konsolenfenster
    icon=ICON,
)
coll = COLLECT(exe, a.binaries, a.datas, name="MagicBox")  # noqa: F821
