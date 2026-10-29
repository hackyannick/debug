"""Analyse von Quelltext/Skripten: Struktur, Abhängigkeiten, verdächtige Muster."""

from __future__ import annotations

import ast
import re

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip
from .identify import source_language

SUSPICIOUS = [
    (re.compile(r"\b(eval|exec)\s*\("), "low", "Dynamische Code-Ausführung (eval/exec)"),
    (re.compile(r"base64\s*[._-]?\s*(b64)?decode|FromBase64String|atob\(", re.I), "low", "Base64-Dekodierung"),
    (re.compile(r"powershell[^\n]{0,40}-(e|enc|encodedcommand)\b", re.I), "high", "PowerShell mit kodiertem Befehl"),
    (re.compile(r"Invoke-Expression|\bIEX\b", re.I), "medium", "PowerShell Invoke-Expression"),
    (re.compile(r"DownloadString|DownloadFile|Invoke-WebRequest|urllib\.request|requests\.(get|post)|fetch\(|curl |wget ", re.I),
     "info", "Lädt Daten aus dem Netz"),
    (re.compile(r"subprocess|os\.system|child_process|Runtime\.getRuntime\(\)\.exec|ShellExecute|WScript\.Shell", re.I),
     "low", "Startet Prozesse/Shell-Befehle"),
    (re.compile(r"(?:\\x[0-9a-f]{2}){20,}", re.I), "medium", "Lange Hex-kodierte Byte-Folgen (Shellcode/Obfuskation?)"),
    (re.compile(r"[A-Za-z0-9+/]{400,}={0,2}"), "low", "Sehr lange Base64-Blöcke (eingebettete Daten?)"),
    (re.compile(r"(?i)(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "medium",
     "Hart kodierte Zugangsdaten"),
]

# Software-Profil: neutrale Beschreibung statt Verdachtsmustern
TECHNIQUES = [
    (re.compile(r"DownloadString|DownloadFile|Invoke-WebRequest|urllib\.request|requests\.(get|post)|fetch\(|"
                r"XMLHttpRequest|axios|https?\.request|net\.request|WebSocket\(", re.I), "Netzwerkzugriffe (HTTP/WebSocket)"),
    (re.compile(r"subprocess|os\.system|child_process|Runtime\.getRuntime\(\)\.exec|ShellExecute|WScript\.Shell", re.I),
     "Startet andere Programme/Prozesse"),
    (re.compile(r"\bfs\.(?:read|write|unlink|mkdir|rename|copy|stat|exists)|open\(|File\.(?:Read|Write)", re.I),
     "Datei-Zugriffe"),
    (re.compile(r"\bcrypto\.|createHash|createCipher|subtle\.|hashlib|Cipher\b", re.I), "Kryptografie/Hashing"),
    (re.compile(r"localStorage|indexedDB|sqlite|\.db\b|Database\(", re.I), "Lokale Datenspeicherung"),
    (re.compile(r"Worker\(|worker_threads|Thread\(|threading\.", re.I), "Nebenläufigkeit (Worker/Threads)"),
]
MINIFIED_LINE = 2000


def beautify(text: str) -> str:
    """Grober Zeilenumbruch für minifizierten Code (nach ; { }) – nur zum Lesen, kein exakter Formatierer."""
    out = []
    for line in text.splitlines():
        if len(line) <= MINIFIED_LINE:
            out.append(line)
            continue
        out.append(re.sub(r"([;{}])(?=\S)", "\\1\n", line))
    return "\n".join(out)


OUTLINE_PATTERNS = {
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|class\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()", re.M),
    "typescript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|class\s+(\w+)|interface\s+(\w+))", re.M),
    "bash": re.compile(r"^\s*(?:function\s+)?(\w+)\s*\(\)\s*\{", re.M),
    "powershell": re.compile(r"^\s*function\s+([\w-]+)", re.M | re.I),
    "php": re.compile(r"^\s*(?:public|private|protected|static|\s)*function\s+(\w+)|^\s*class\s+(\w+)", re.M),
    "go": re.compile(r"^func\s+(?:\([^)]*\)\s*)?(\w+)|^type\s+(\w+)\s+struct", re.M),
    "rust": re.compile(r"^\s*(?:pub\s+)?(?:fn\s+(\w+)|struct\s+(\w+)|enum\s+(\w+)|impl\s+(\w+))", re.M),
    "java": re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:class|interface|enum)\s+(\w+)|^\s*(?:public|private|protected)\s+[\w<>\[\], ]+\s+(\w+)\s*\(", re.M),
    "csharp": re.compile(r"^\s*(?:public|private|protected|internal)?\s*(?:static\s+)?(?:class|interface|struct|enum)\s+(\w+)|^\s*(?:public|private|protected|internal)\s+[\w<>\[\], ]+\s+(\w+)\s*\(", re.M),
    "c": re.compile(r"^[\w\*][\w\s\*]*?\b(\w+)\s*\([^;]*\)\s*\{", re.M),
    "cpp": re.compile(r"^[\w\*:<>][\w\s\*:<>,]*?\b([\w:~]+)\s*\([^;]*\)\s*(?:const\s*)?\{", re.M),
}

IMPORT_PATTERNS = {
    "javascript": re.compile(r"(?:require\(\s*['\"]([^'\"]+)|from\s+['\"]([^'\"]+)|import\s+['\"]([^'\"]+))"),
    "typescript": re.compile(r"(?:require\(\s*['\"]([^'\"]+)|from\s+['\"]([^'\"]+))"),
    "java": re.compile(r"^import\s+(?:static\s+)?([\w.]+)", re.M),
    "go": re.compile(r"^\s*\"([\w./-]+)\"$|^import\s+\"([^\"]+)\"", re.M),
    "rust": re.compile(r"^use\s+([\w:]+)", re.M),
    "c": re.compile(r"^#include\s+[<\"]([^>\"]+)", re.M),
    "cpp": re.compile(r"^#include\s+[<\"]([^>\"]+)", re.M),
    "csharp": re.compile(r"^using\s+([\w.]+);", re.M),
    "php": re.compile(r"^\s*(?:use|require(?:_once)?|include(?:_once)?)\s*\(?\s*['\"]?([\w\\/.]+)", re.M),
}


def _decode(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def python_outline(text: str) -> tuple[list[str], list[str]]:
    tree = ast.parse(text)
    imports: list[str] = []
    outline: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or ".")

    def visit(nodes, indent=""):
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                doc = ast.get_docstring(node)
                outline.append(f"{indent}class {node.name}" + (f"  # {clip(doc.splitlines()[0], 80)}" if doc else ""))
                visit(node.body, indent + "    ")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = ", ".join(a.arg for a in node.args.args)
                doc = ast.get_docstring(node)
                prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
                outline.append(f"{indent}{prefix} {node.name}({args})" + (f"  # {clip(doc.splitlines()[0], 80)}" if doc else ""))

    visit(tree.body)
    return sorted(set(imports)), outline


class SourceAnalyzer(Analyzer):
    name = "source"
    kinds = ("source", "text")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        text = _decode(ctx.data)
        lang = source_language(ctx.data, ctx.path.name) or "text"
        lines = text.splitlines()
        ctx.facts["language"] = lang
        longest = max((len(l) for l in lines), default=0)
        minified = longest > MINIFIED_LINE and len(text) > 20_000
        ctx.facts["minified"] = minified
        kv = {"Sprache": lang, "Zeilen": str(len(lines)), "Längste Zeile": f"{longest} Zeichen"}
        if minified:
            kv["Form"] = ("minifiziert/gebündelt (z. B. webpack) – unten zur Lesbarkeit umbrochen; "
                          "Variablennamen sind verkürzt, Zeichenketten und API-Namen bleiben erhalten")

        imports: list[str] = []
        outline: list[str] = []
        if lang == "python":
            try:
                imports, outline = python_outline(text)
            except SyntaxError as exc:
                kv["Hinweis"] = f"Python-Syntaxfehler in Zeile {exc.lineno} – evtl. Python 2 oder beschädigt"
        else:
            if lang in IMPORT_PATTERNS:
                imports = sorted({next(g for g in m.groups() if g) for m in IMPORT_PATTERNS[lang].finditer(text)
                                  if any(m.groups())})
            if lang in OUTLINE_PATTERNS:
                outline = [next(g for g in m.groups() if g) for m in OUTLINE_PATTERNS[lang].finditer(text)
                           if any(m.groups())]
                outline = [o for o in outline if o not in ("if", "for", "while", "switch", "return", "sizeof")]
        result.add(Section("Quelltext-Überblick", kv=kv, llm_priority=0))
        if imports:
            result.add(Section("Abhängigkeiten / Imports", text=", ".join(imports), llm_priority=0))
        if outline:
            result.add(Section("Struktur (Klassen & Funktionen)", code="\n".join(outline[:400]),
                               code_lang=lang, llm_priority=1))

        if result.profile == "allgemein":
            used = []
            for rx, label in TECHNIQUES:
                n = len(rx.findall(text))
                if n:
                    used.append([label, str(n)])
            if used:
                result.add(Section("Verwendete Techniken", table=Table(["Technik", "Fundstellen"], used),
                                   llm_priority=0))
            result.add(Section("Quelltext (zur Lesbarkeit umbrochen)" if minified else "Quelltext",
                               code=beautify(text) if minified else text, code_lang=lang, llm_priority=2))
            return

        hits = []
        for rx, sev, label in SUSPICIOUS:
            matches = list(rx.finditer(text))
            if matches:
                line_no = text.count("\n", 0, matches[0].start()) + 1
                hits.append([label, str(len(matches)), f"Zeile {line_no}"])
                if sev != "info":
                    result.find(sev, label, f"{len(matches)} Treffer, erstmals in Zeile {line_no}")
        if hits:
            result.add(Section("Auffällige Muster", table=Table(["Muster", "Treffer", "Erstes Vorkommen"], hits),
                               llm_priority=0))
        if lines and max(len(l) for l in lines) > 5000 and len(lines) < 20:
            result.find("medium", "Minifiziert oder obfuskiert", "Extrem lange Zeilen – Code wurde vermutlich verschleiert/minifiziert.")

        result.add(Section("Quelltext (zur Lesbarkeit umbrochen)" if minified else "Quelltext",
                           code=beautify(text) if minified else text, code_lang=lang, llm_priority=2))


class PDFAnalyzer(Analyzer):
    """Schlüsselwort-Scan à la pdfid: zeigt aktive Inhalte in PDFs."""

    name = "pdf"
    kinds = ("pdf",)
    KEYWORDS = {
        b"/JavaScript": ("high", "Enthält JavaScript"), b"/JS": ("medium", "JavaScript-Referenz"),
        b"/OpenAction": ("low", "Aktion beim Öffnen"), b"/AA": ("low", "Automatische Aktionen"),
        b"/Launch": ("high", "Startet externe Programme"), b"/EmbeddedFile": ("medium", "Eingebettete Dateien"),
        b"/URI": ("info", "Enthält Links"), b"/SubmitForm": ("low", "Sendet Formulardaten"),
        b"/AcroForm": ("info", "Formular"), b"/XFA": ("low", "XFA-Formular"), b"/Encrypt": ("low", "Verschlüsselt"),
        b"/ObjStm": ("info", "Objekt-Streams (können Inhalte verbergen)"), b"/RichMedia": ("medium", "Flash/RichMedia"),
    }

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        data = ctx.data
        rows = [["Version", data[5:8].decode(errors="replace")],
                ["Objekte", str(data.count(b" obj"))], ["Seiten (ca.)", str(data.count(b"/Type /Page") + data.count(b"/Type/Page") - data.count(b"/Type /Pages") - data.count(b"/Type/Pages"))]]
        for kw, (sev, label) in self.KEYWORDS.items():
            n = len(re.findall(re.escape(kw) + rb"(?![A-Za-z])", data))
            if n:
                rows.append([f"{kw.decode()} – {label}", str(n)])
                if sev in ("medium", "high"):
                    result.find(sev, f"PDF: {label}", f"{n}× {kw.decode()}")
        result.add(Section("PDF-Struktur", table=Table(["Merkmal", "Wert"], rows), llm_priority=0))
