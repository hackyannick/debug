""".NET-Assemblies: Metadaten mit dnfile und (optional) Dekompilierung nach C# mit ilspycmd."""

from __future__ import annotations

import os
import subprocess
import tempfile

from magicbox import tools
from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip

try:
    import dnfile
except ImportError:  # pragma: no cover
    dnfile = None

# Typen/Methoden, die in .NET-Malware typisch sind -> (Severity, Erklärung)
SUSPICIOUS_REFS = {
    "Assembly.Load": ("medium", "Lädt Code zur Laufzeit aus Bytes (typisch für Loader/Stager)"),
    "Process.Start": ("low", "Startet Prozesse"),
    "WebClient.DownloadData": ("low", "Lädt Daten aus dem Netz"),
    "WebClient.DownloadString": ("low", "Lädt Daten aus dem Netz"),
    "WebClient.DownloadFile": ("low", "Lädt Dateien aus dem Netz"),
    "HttpClient.PostAsync": ("low", "Sendet Daten per HTTP POST"),
    "Registry.SetValue": ("low", "Schreibt in die Registry"),
    "RegistryKey.SetValue": ("low", "Schreibt in die Registry"),
    "ProtectedData.Unprotect": ("high", "Entschlüsselt DPAPI-Daten (typisch: gespeicherte Browser-Passwörter)"),
    "Marshal.GetDelegateForFunctionPointer": ("medium", "Ruft nativen Code über Funktionszeiger auf"),
    "Convert.FromBase64String": ("info", "Dekodiert Base64"),
    "Clipboard.GetText": ("medium", "Liest die Zwischenablage"),
    "Screen.PrimaryScreen": ("low", "Greift auf den Bildschirm zu (Screenshots?)"),
    "Graphics.CopyFromScreen": ("medium", "Erstellt Screenshots"),
    "SmtpClient.Send": ("medium", "Versendet E-Mails (häufiger Exfiltrationsweg bei Stealern)"),
    "FtpWebRequest.Create": ("low", "FTP-Verbindung"),
    "Debugger.IsAttached": ("low", "Prüft auf Debugger"),
}


def _user_strings(data: bytes) -> list[str]:
    """Liest den #US-Heap (String-Literale im Code) – bei .NET-Malware oft die Konfiguration (C2, Keys …)."""
    out, off = [], 1
    while off < len(data):
        b = data[off]
        if b & 0x80 == 0:
            length, hdr = b, 1
        elif b & 0xC0 == 0x80 and off + 1 < len(data):
            length, hdr = ((b & 0x3F) << 8) | data[off + 1], 2
        elif off + 3 < len(data):
            length, hdr = ((b & 0x1F) << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3], 4
        else:
            break
        if length == 0:
            off += hdr
            continue
        raw = data[off + hdr: off + hdr + length - 1]
        s = raw.decode("utf-16-le", "replace").strip()
        if s:
            out.append(s)
        off += hdr + length
    return out


class DotNetAnalyzer(Analyzer):
    name = "dotnet"
    kinds = ("pe",)

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return super().matches(ctx, result) and ctx.facts.get("dotnet", False)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if dnfile is not None:
            self._metadata(ctx, result)
        else:
            result.errors.append("dnfile nicht installiert – .NET-Metadaten übersprungen (pip install dnfile).")
        self._decompile(ctx, result)

    def _metadata(self, ctx: Context, result: AnalysisResult) -> None:
        pe = dnfile.dnPE(data=ctx.data)
        net = pe.net
        if net is None or net.mdtables is None:
            return
        result.tools.append("dnfile")
        t = net.mdtables
        kv = {}
        if t.Assembly:
            a = t.Assembly[0]
            kv["Assembly"] = f"{a.Name} {a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}"
        if t.AssemblyRef:
            kv["Referenzierte Assemblies"] = ", ".join(sorted({str(r.Name) for r in t.AssemblyRef}))
        version = getattr(getattr(net.metadata, "struct", None), "Version", b"")
        if version:
            kv["Runtime-Version"] = version.rstrip(b"\0").decode(errors="replace")
        if kv:
            result.add(Section(".NET-Assembly", kv=kv, llm_priority=0))

        outline, n_types = [], 0
        for td in t.TypeDef or []:
            name = str(td.TypeName)
            if name == "<Module>":
                continue
            n_types += 1
            ns = str(td.TypeNamespace)
            methods = [str(m.row.Name) for m in td.MethodList if m.row is not None]
            fields = [str(f.row.Name) for f in td.FieldList if f.row is not None]
            outline.append(f"class {ns + '.' if ns else ''}{name}")
            if fields:
                outline.append("    Felder: " + clip(", ".join(fields), 300))
            if methods:
                outline.append("    Methoden: " + clip(", ".join(methods), 500))
        if outline:
            result.add(Section(f".NET-Klassen ({n_types})", code="\n".join(outline[:600]), code_lang="text",
                               llm_priority=1))
        # Obfuskatoren erkennt man oft an unlesbaren Namen
        weird = sum(1 for td in t.TypeDef or [] if not str(td.TypeName).isascii() or len(str(td.TypeName)) > 40)
        if n_types and weird / n_types > 0.3:
            result.find("medium", ".NET-Code ist obfuskiert", f"{weird} von {n_types} Klassennamen sind unlesbar/zufällig.")

        refs = set()
        for r in t.MemberRef or []:
            parent = getattr(getattr(r, "Class", None), "row", None)
            tname = str(getattr(parent, "TypeName", "")) if parent is not None else ""
            if tname:
                refs.add(f"{tname}.{r.Name}")
        hits = sorted(r for r in refs if r in SUSPICIOUS_REFS)
        if refs:
            result.add(Section("Aufgerufene .NET-APIs", text=clip(", ".join(sorted(refs)), 5000), llm_priority=1))
        for h in hits:
            sev, why = SUSPICIOUS_REFS[h]
            result.find(sev, f".NET: {h}", why)

        us = net.user_strings
        strings = _user_strings(us.__data__) if us is not None else []
        if strings:
            ctx.facts.setdefault("extra_strings", []).extend(strings)
            result.add(Section(f"String-Literale im Code ({len(strings)})",
                               code="\n".join(clip(s, 200) for s in strings[:400]), code_lang="text", llm_priority=0))

    def _decompile(self, ctx: Context, result: AnalysisResult) -> None:
        ilspy = tools.which(ctx.settings.ilspy_path)
        if not ilspy:
            return
        fd, tmp = tempfile.mkstemp(prefix="magicbox_", suffix=".dll")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(ctx.data)
            proc = tools.run([ilspy, tmp], timeout=ctx.settings.tool_timeout_s)
        except subprocess.TimeoutExpired:
            result.errors.append("ilspycmd: Zeitlimit überschritten")
            return
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        code = proc.stdout.strip()
        if proc.returncode != 0 or not code:
            result.errors.append(f"ilspycmd fehlgeschlagen: {clip(proc.stderr.strip(), 300)}")
            return
        # Assembly-Attribut-Rauschen am Anfang entfernen
        lines = [l for l in code.splitlines() if not l.startswith(("[assembly:", "[module:"))]
        result.tools.append("ilspycmd")
        result.add(Section("Dekompilierter C#-Code (ILSpy)", code="\n".join(lines), code_lang="csharp", llm_priority=1))


class OfficeMacroAnalyzer(Analyzer):
    """VBA- und Excel-4.0-(XLM-)Makros mit oletools/olevba extrahieren und bewerten."""

    name = "olevba"
    kinds = ("ole", "zip", "rtf", "source", "text")

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        if not super().matches(ctx, result):
            return False
        name = ctx.path.name.lower()
        if result.kind == "zip":
            return name.endswith((".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".xlsb", ".dotm", ".xltm"))
        if result.kind in ("source", "text"):
            return name.endswith((".vba", ".bas", ".frm", ".cls", ".vbs"))
        return True

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        try:
            from oletools.olevba import VBA_Parser
        except ImportError:
            if result.kind == "ole":
                result.errors.append("oletools nicht installiert – Makro-Analyse übersprungen (pip install oletools).")
            return
        try:
            vba = VBA_Parser(ctx.path.name, data=ctx.data)
        except Exception as exc:  # olevba wirft bei unbekannten Formaten generische Fehler
            result.errors.append(f"olevba: {exc}")
            return
        try:
            if not vba.detect_vba_macros():
                return
            result.tools.append("olevba")
            is_text = result.kind in ("source", "text")
            blocks = []
            for _fn, stream, vba_name, code in vba.extract_all_macros():
                if code and code.strip():
                    blocks.append(f"' ===== {vba_name} ({stream}) =====\n{code.strip()}")
            if blocks and not is_text:  # bei Skriptdateien steht der Code schon im Abschnitt „Quelltext“
                result.add(Section("Makro-Code (VBA/XLM)", code="\n\n".join(blocks), code_lang="vb", llm_priority=0))
                # Makro-Code ist im Dokument komprimiert – für IOC-Suche/Deobfuskation als Text bereitstellen
                ctx.facts.setdefault("extra_strings", []).extend("\n".join(blocks).splitlines())
            rows, suspicious = [], []
            for kind, keyword, description in vba.analyze_macros():
                rows.append([kind, clip(str(keyword), 120), clip(str(description), 200)])
                if kind == "AutoExec":
                    result.find("high", f"Makro startet automatisch ({keyword})", description)
                elif kind == "Suspicious":
                    suspicious.append(str(keyword))
            if suspicious:
                result.find("medium", "Verdächtige Makro-Funktionen", ", ".join(dict.fromkeys(suspicious)))
            if rows:
                result.add(Section("Makro-Bewertung (olevba)", table=Table(["Typ", "Schlüsselwort", "Beschreibung"], rows),
                                   llm_priority=0))
            if not is_text:
                result.find("high", "Dokument enthält Makros", f"{len(blocks)} Makro-Modul(e) extrahiert.")
        finally:
            vba.close()
