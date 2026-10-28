"""Registry aller Analyzer – Reihenfolge ist relevant (radare2 vor PE/ELF, damit Capstone dann entfällt)."""

from .archive import ArchiveAnalyzer
from .elf import ELFAnalyzer
from .identify import IdentifyAnalyzer
from .java import JavaClassAnalyzer
from .macho import MachOAnalyzer
from .pe import PEAnalyzer
from .radare2 import Radare2Analyzer
from .source import PDFAnalyzer, SourceAnalyzer
from .strings import StringsAnalyzer

ANALYZERS = [
    Radare2Analyzer(),
    PEAnalyzer(),
    ELFAnalyzer(),
    MachOAnalyzer(),
    JavaClassAnalyzer(),
    PDFAnalyzer(),
    SourceAnalyzer(),
    StringsAnalyzer(),
    ArchiveAnalyzer(),
]

__all__ = ["ANALYZERS", "IdentifyAnalyzer"]
