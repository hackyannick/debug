"""Erzeugt den Bericht als Markdown, HTML (eigenständig, schön) und JSON."""

from __future__ import annotations

import csv
import datetime as dt
import html
import json
import re
from dataclasses import dataclass
from pathlib import Path

from magicbox import __version__
from magicbox.analyzers.base import human_size
from magicbox.model import AnalysisResult, Section

try:
    import markdown as md_lib
    from markdown.extensions import Extension
    from markdown.treeprocessors import Treeprocessor
except ImportError:  # pragma: no cover
    md_lib = None

SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}
SEV_NAME = {"high": "hoch", "medium": "mittel", "low": "niedrig", "info": "Info"}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_CODE_LINES = 400


@dataclass
class ReportFiles:
    folder: Path
    markdown: Path
    html: Path
    json: Path
    iocs: Path


def _cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _section_md(sec: Section, level: int) -> str:
    h = "#" * level
    out = [f"{h} {sec.title}", ""]
    if sec.kv:
        out += ["| Merkmal | Wert |", "|---|---|"]
        out += [f"| {_cell(k)} | {_cell(v)} |" for k, v in sec.kv.items()]
        out.append("")
    if sec.table:
        out.append("| " + " | ".join(_cell(x) for x in sec.table.headers) + " |")
        out.append("|" + "---|" * len(sec.table.headers))
        out += ["| " + " | ".join(_cell(x) for x in row) + " |" for row in sec.table.rows]
        if sec.table.total and sec.table.total > len(sec.table.rows):
            out.append(f"\n*… {sec.table.total - len(sec.table.rows)} weitere Einträge nicht dargestellt.*")
        out.append("")
    if sec.text:
        out += [sec.text, ""]
    if sec.code:
        lines = sec.code.splitlines()
        code = "\n".join(lines[:MAX_CODE_LINES]).replace("```", "``\u200b`")
        out += [f"```{sec.code_lang}", code, "```"]
        if len(lines) > MAX_CODE_LINES:
            out.append(f"*… {len(lines) - MAX_CODE_LINES} weitere Zeilen (vollständig in analysis.json).*")
        out.append("")
    return "\n".join(out)


def _all_findings(result: AnalysisResult):
    for r in result.walk():
        for f in r.findings:
            yield r, f


def defang(kind: str, value: str) -> str:
    """Entschärft IOCs, damit sie nicht versehentlich anklickbar/auflösbar sind (hxxp://evil[.]com)."""
    if kind == "URL":
        scheme, sep, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        return scheme.replace("http", "hxxp").replace("ftp", "fxp") + sep + host.replace(".", "[.]") + slash + path
    if kind in ("Domain", "IPv4"):
        return value.replace(".", "[.]")
    if kind == "E-Mail":
        user, _, dom = value.partition("@")
        return f"{user}[@]{dom.replace('.', '[.]')}"
    return value


def all_iocs(result: AnalysisResult) -> list[tuple[str, str, str]]:
    """(Typ, Wert, Datei) über alle (auch verschachtelten) Dateien, ohne Duplikate."""
    seen, out = set(), []
    for r in result.walk():
        for kind, values in r.iocs.items():
            for v in values:
                if (kind, v) not in seen:
                    seen.add((kind, v))
                    out.append((kind, v, r.name))
    return out


def _ioc_md(result: AnalysisResult) -> list[str]:
    iocs = all_iocs(result)
    files = [r for r in result.walk() if r.hashes]
    if not iocs and len(files) <= 1:
        return []
    out = ["## Indikatoren (IOCs)", "",
           "*Werte sind entschärft (z. B. `hxxp://evil[.]com`). Unverändert als CSV: `iocs.csv` im Berichtsordner.*", ""]
    if iocs:
        out += ["| Typ | Wert | gefunden in |", "|---|---|---|"]
        for kind, value, src in iocs[:400]:
            out.append(f"| {kind} | `{_cell(defang(kind, value))}` | {_cell(src)} |")
        if len(iocs) > 400:
            out.append(f"\n*… {len(iocs) - 400} weitere in iocs.csv*")
        out.append("")
    out += ["**Datei-Hashes**", "", "| Datei | SHA-256 | MD5 |", "|---|---|---|"]
    out += [f"| {_cell(r.name)} | `{r.hashes['sha256']}` | `{r.hashes['md5']}` |" for r in files[:200]]
    out.append("")
    return out


def rule_based_summary(result: AnalysisResult) -> str:
    """Kurzfassung ohne KI – aus den Fakten abgeleitet."""
    lines = [f"**{result.name}** ist ein(e) **{result.description}** mit {human_size(result.size)}."]
    caps = [s for s in result.sections if s.title.startswith("Abgeleitete Fähigkeiten")]
    if caps and caps[0].table:
        lines.append("Erkennbare Fähigkeiten: " + ", ".join(r[0] for r in caps[0].table.rows) + ".")
    if result.children:
        kinds: dict[str, int] = {}
        for c in result.walk():
            if c is not result:
                kinds[c.description] = kinds.get(c.description, 0) + 1
        top = sorted(kinds.items(), key=lambda kv: -kv[1])[:6]
        lines.append(f"Enthält {sum(kinds.values())} Dateien, u. a.: " + ", ".join(f"{n}× {d}" for d, n in top) + ".")
    if result.profile == "allgemein":
        lines.append("📘 Software-Dokumentation – Malware-Prüfungen (YARA, capa, IOCs, Deobfuskierung) und "
                     "Risikobewertung sind in diesem Profil abgeschaltet.")
        return "\n\n".join(lines)
    detections = sorted({d for r in result.walk() for d in r.detections})
    if detections:
        lines.append("YARA-Treffer: " + ", ".join(f"`{d}`" for d in detections) + ".")
    counts = {sev: 0 for sev in SEV_ORDER}
    for _, f in _all_findings(result):
        counts[f.severity] += 1
    if counts["high"]:
        verdict = "🔴 **Gefährliche Merkmale gefunden** – genauer prüfen, nur in isolierter Umgebung ausführen."
    elif counts["medium"]:
        verdict = "🟠 **Auffällig** – einige Merkmale sollten geprüft werden."
    else:
        verdict = "🟢 **Keine kritischen Auffälligkeiten** in der statischen Analyse."
    lines.append(verdict + f" ({counts['high']} hoch, {counts['medium']} mittel, {counts['low']} niedrig)")
    return "\n\n".join(lines)


def build_markdown(result: AnalysisResult, llm_error: str = "") -> str:
    now = dt.datetime.now().strftime("%d.%m.%Y %H:%M")
    out = [f"# Analysebericht: {result.name}", "",
           f"*Erstellt mit Magic Box {__version__} am {now}"
           + (f" · KI-Modell: {result.llm_model}" if result.llm_model else " · ohne KI") + "*", ""]
    if result.hashes:
        out.append(f"`SHA-256: {result.hashes.get('sha256', '')}`\n")

    out += _qa_md(result)
    out += ["## Auf einen Blick", "", rule_based_summary(result), ""]

    if result.llm_doc:
        doc = result.llm_doc.strip()
        # Überschriften des Modells eine Ebene tiefer hängen, falls es mit "# " beginnt
        if re.search(r"^# ", doc, re.M):
            doc = re.sub(r"^(#+) ", r"#\1 ", doc, flags=re.M)
        out += ["---", "", doc, "",
                "> ℹ️ Dieser Teil wurde von einem KI-Modell aus den statischen Analysedaten formuliert. "
                "Aussagen mit „vermutlich“ sind Interpretationen – die Fakten stehen im technischen Anhang.", ""]
    elif llm_error:
        out += [f"> ⚠️ KI-Dokumentation nicht verfügbar: {llm_error}", ""]

    findings = sorted(_all_findings(result), key=lambda rf: SEV_ORDER[rf[1].severity])
    if findings and result.profile == "allgemein":
        out += ["## Technische Hinweise", "", "| Datei | Hinweis | Details |", "|---|---|---|"]
        out += [f"| {_cell(r.name)} | {_cell(f.title)} | {_cell(f.detail)} |" for r, f in findings]
        out.append("")
    elif findings:
        out += ["## Auffälligkeiten", "", "| Stufe | Datei | Befund | Details |", "|---|---|---|---|"]
        for r, f in findings:
            out.append(f"| {SEV_ICON[f.severity]} {SEV_NAME[f.severity]} | {_cell(r.name)} | {_cell(f.title)} | {_cell(f.detail)} |")
        out.append("")

    if result.profile != "allgemein":
        out += _ioc_md(result)
    out += ["---", "", "## Technischer Anhang", ""]
    out += _result_md(result, 3)
    return "\n".join(out)


def _qa_md(result: AnalysisResult) -> list[str]:
    """Eigene Fragen an die KI – neueste zuerst, ganz oben, weil gezielt gefragt."""
    if not result.qa:
        return []
    out = ["## ❓ Deine Fragen an die KI", ""]
    for item in reversed(result.qa):
        question = str(item.get("question", "")).strip().replace("\n", "\n> ")
        when = dt.datetime.fromtimestamp(item["time"]).strftime("%d.%m.%Y %H:%M") if item.get("time") else ""
        answer = str(item.get("answer", "")).strip()
        # Überschriften der Antwort unter die Frage hängen (mindestens Ebene 4)
        answer = re.sub(r"^(#{1,3}) ", lambda m: "#" * min(len(m.group(1)) + 3, 6) + " ", answer, flags=re.M)
        meta = " · ".join(x for x in (when, item.get("model", "")) if x)
        out += [f"> **Frage:** {question}", "", answer or "*(keine Antwort)*", ""]
        if meta:
            out += [f"*{meta}*", ""]
        out += ["---", ""]
    return out


def _result_md(result: AnalysisResult, level: int) -> list[str]:
    out = []
    for sec in result.sections:
        out.append(_section_md(sec, level))
    if result.tools:
        out.append(f"*Verwendete Werkzeuge: {', '.join(dict.fromkeys(result.tools))}*\n")
    if result.errors:
        out += [f"{'#' * level} Hinweise zur Analyse", ""] + [f"- {e}" for e in result.errors] + [""]
    for child in result.children:
        out += [f"{'#' * min(level, 6)} 📄 {child.name}", "", f"*{child.description}*", ""]
        if child.llm_doc:
            out += ["**KI-Einschätzung:**", "", child.llm_doc, ""]
        out += _result_md(child, min(level + 1, 6))
    return out


# --------------------------------------------------------------------------- HTML

SAFE_SCHEMES = ("http://", "https://", "mailto:", "#")

if md_lib is not None:
    class _SanitizeLinks(Treeprocessor):
        def run(self, root):
            for el in root.iter():
                if el.tag == "a" and not el.get("href", "").strip().lower().startswith(SAFE_SCHEMES):
                    el.attrib.pop("href", None)
                elif el.tag == "img":  # keine (Remote-)Bilder laden
                    el.tag, el.text = "span", f"[Bild: {el.get('alt', '')}]"
                    el.attrib.clear()

    class NoRawHtml(Extension):
        """Analysierte Dateien und LLM-Ausgaben sind nicht vertrauenswürdig: kein rohes HTML durchreichen."""

        def extendMarkdown(self, md):
            md.preprocessors.deregister("html_block")
            md.inlinePatterns.deregister("html")
            md.treeprocessors.register(_SanitizeLinks(md), "sanitize_links", 0)


def markdown_to_html(text: str) -> str:
    if md_lib is None:
        return f"<pre>{html.escape(text)}</pre>"
    return md_lib.markdown(text, extensions=["tables", "fenced_code", "sane_lists", "toc", NoRawHtml()],
                           extension_configs={"toc": {"permalink": False}})


def build_html(markdown_text: str, title: str) -> str:
    css = (Path(__file__).with_name("style.css")).read_text(encoding="utf-8")
    body = markdown_to_html(markdown_text)
    return (
        "<!doctype html>\n<html lang=\"de\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        f"<title>{html.escape(title)}</title><style>{css}</style></head>"
        f"<body><main class=\"doc\">{body}</main></body></html>"
    )


def build_classic_html(markdown_text: str, title: str) -> str:
    """Bericht für die native Windows-App (WebBrowser-Steuerelement = IE-Engine) im Office-2003-Stil."""
    css = (Path(__file__).with_name("classic.css")).read_text(encoding="utf-8")
    body = markdown_to_html(markdown_text)
    return (
        "<!DOCTYPE html>\n<html lang=\"de\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        f"<title>{html.escape(title)}</title><style>{css}</style></head>"
        f"<body><div class=\"doc\">{body}</div></body></html>"
    )


def build_qt_html(markdown_text: str) -> str:
    """Vereinfachtes HTML für die Vorschau in Qt (QTextBrowser kann nur einfaches CSS)."""
    body = markdown_to_html(markdown_text)
    style = (
        "body{font-family:'Segoe UI','Noto Sans',sans-serif;font-size:10.5pt;}"
        "h1{font-size:20pt;color:#4c1d95;} h2{font-size:15pt;color:#5b21b6;margin-top:18px;}"
        "h3{font-size:12.5pt;color:#6d28d9;} h4{font-size:11pt;}"
        "table{border-collapse:collapse;margin:6px 0;} th{background:#ede9fe;}"
        "td,th{border:1px solid #c4b5fd;padding:3px 6px;}"
        "pre{background:#f5f3ff;padding:8px;font-family:Consolas,'DejaVu Sans Mono',monospace;font-size:9pt;}"
        "code{font-family:Consolas,'DejaVu Sans Mono',monospace;background:#f5f3ff;}"
        "blockquote{color:#555;margin-left:10px;}"
    )
    return f"<html><head><style>{style}</style></head><body>{body}</body></html>"


# --------------------------------------------------------------------------- Ausgabe

def safe_name(name: str) -> str:
    cleaned = re.sub(r"[^\w.-]+", "_", name).strip("._") or "datei"
    return cleaned[:60]


def write_report(result: AnalysisResult, out_dir: Path, llm_error: str = "", folder: Path | None = None) -> ReportFiles:
    """Schreibt den Bericht in ``folder`` bzw. einen neuen Unterordner von ``out_dir``."""
    if folder is None:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        folder = Path(out_dir).expanduser() / f"{safe_name(result.name)}_{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    md_text = build_markdown(result, llm_error)
    files = ReportFiles(folder, folder / "bericht.md", folder / "bericht.html", folder / "analysis.json",
                        folder / "iocs.csv")
    files.markdown.write_text(md_text, encoding="utf-8")
    files.html.write_text(build_html(md_text, f"Analyse: {result.name}"), encoding="utf-8")
    files.json.write_text(json.dumps(result.to_dict(), indent=1, ensure_ascii=False), encoding="utf-8")
    with files.iocs.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["typ", "wert", "datei"])
        w.writerows(all_iocs(result))
        for r in result.walk():
            if r.hashes:
                w.writerow(["SHA-256", r.hashes["sha256"], r.name])
    return files
