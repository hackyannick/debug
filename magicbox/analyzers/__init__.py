"""Registry aller Analyzer – die Reihenfolge ist relevant:

* radare2 vor PE/ELF (Capstone-Disassembly bekommt dann niedrigere LLM-Priorität)
* PE vor .NET (setzt ``facts["dotnet"]``), .NET vor Deobfuskation (String-Literale)
* Strings/Quelltext vor IOC-Extraktion
* Entpacker und Archive zuletzt (rekursive Kind-Analysen)
"""

from .archive import ArchiveAnalyzer
from .asar import AsarAnalyzer
from .capa import CapaAnalyzer
from .deobfuscate import DeobfuscationAnalyzer
from .dotnet import DotNetAnalyzer, OfficeMacroAnalyzer
from .elf import ELFAnalyzer
from .identify import IdentifyAnalyzer
from .installer import InstallerAnalyzer
from .jsbundle import JSBundleAnalyzer
from .iocs import IOCAnalyzer
from .java import JavaClassAnalyzer
from .macho import MachOAnalyzer
from .pe import PEAnalyzer
from .radare2 import Radare2Analyzer
from .runtime import RuntimeAnalyzer
from .source import PDFAnalyzer, SourceAnalyzer
from .strings import StringsAnalyzer
from .unpack import UPXUnpacker
from .yara_scan import YaraAnalyzer

ANALYZERS = [
    RuntimeAnalyzer(),  # zuerst: entscheidet, ob sich Disassembly überhaupt lohnt
    Radare2Analyzer(),
    PEAnalyzer(),
    ELFAnalyzer(),
    MachOAnalyzer(),
    DotNetAnalyzer(),
    JavaClassAnalyzer(),
    PDFAnalyzer(),
    SourceAnalyzer(),
    JSBundleAnalyzer(),  # nach SourceAnalyzer (nutzt die erkannte Sprache)
    OfficeMacroAnalyzer(),
    StringsAnalyzer(),
    DeobfuscationAnalyzer(),
    IOCAnalyzer(),
    YaraAnalyzer(),
    CapaAnalyzer(),
    UPXUnpacker(),
    ArchiveAnalyzer(),
    AsarAnalyzer(),
    InstallerAnalyzer(),
]

__all__ = ["ANALYZERS", "IdentifyAnalyzer"]
