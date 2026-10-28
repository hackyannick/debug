"""Registry aller Analyzer – die Reihenfolge ist relevant:

* radare2 vor PE/ELF (Capstone-Disassembly bekommt dann niedrigere LLM-Priorität)
* PE vor .NET (setzt ``facts["dotnet"]``), .NET vor Deobfuskation (String-Literale)
* Strings/Quelltext vor IOC-Extraktion
* Entpacker und Archive zuletzt (rekursive Kind-Analysen)
"""

from .archive import ArchiveAnalyzer
from .capa import CapaAnalyzer
from .deobfuscate import DeobfuscationAnalyzer
from .dotnet import DotNetAnalyzer, OfficeMacroAnalyzer
from .elf import ELFAnalyzer
from .identify import IdentifyAnalyzer
from .iocs import IOCAnalyzer
from .java import JavaClassAnalyzer
from .macho import MachOAnalyzer
from .pe import PEAnalyzer
from .radare2 import Radare2Analyzer
from .source import PDFAnalyzer, SourceAnalyzer
from .strings import StringsAnalyzer
from .unpack import UPXUnpacker
from .yara_scan import YaraAnalyzer

ANALYZERS = [
    Radare2Analyzer(),
    PEAnalyzer(),
    ELFAnalyzer(),
    MachOAnalyzer(),
    DotNetAnalyzer(),
    JavaClassAnalyzer(),
    PDFAnalyzer(),
    SourceAnalyzer(),
    OfficeMacroAnalyzer(),
    StringsAnalyzer(),
    DeobfuscationAnalyzer(),
    IOCAnalyzer(),
    YaraAnalyzer(),
    CapaAnalyzer(),
    UPXUnpacker(),
    ArchiveAnalyzer(),
]

__all__ = ["ANALYZERS", "IdentifyAnalyzer"]
