"""YARA-Scan mit mitgelieferten Basisregeln und optional eigenen/Community-Regeln (z. B. YARA-Forge)."""

from __future__ import annotations

import os
from pathlib import Path

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

BUILTIN_RULES = Path(__file__).resolve().parent.parent / "yara_rules"
_CACHE: dict[tuple, tuple[list, list[str]]] = {}


def _rule_files(extra_dir: str) -> list[Path]:
    files = sorted(BUILTIN_RULES.glob("*.yar"))
    if extra_dir:
        root = Path(os.path.expanduser(extra_dir))
        if root.is_dir():
            files += sorted(p for p in root.rglob("*") if p.suffix.lower() in (".yar", ".yara"))
    return files


def compile_rules(extra_dir: str):
    """Kompiliert jede Regeldatei einzeln, damit eine kaputte Datei nicht alles blockiert. Ergebnis wird gecacht."""
    files = _rule_files(extra_dir)
    key = tuple((str(f), f.stat().st_mtime) for f in files)
    if key in _CACHE:
        return _CACHE[key]
    compiled, errors = [], []
    for f in files:
        try:
            compiled.append((f.name, yara.compile(filepath=str(f))))
        except yara.Error as exc:
            errors.append(f"{f.name}: {exc}")
    _CACHE.clear()
    _CACHE[key] = (compiled, errors)
    return compiled, errors


def severity_for(match) -> str:
    meta = {k.lower(): str(v).lower() for k, v in (match.meta or {}).items()}
    sev = meta.get("severity") or meta.get("score") or ""
    if sev in ("info", "low", "medium", "high"):
        return sev
    if sev.isdigit():
        n = int(sev)
        return "high" if n >= 75 else "medium" if n >= 50 else "low"
    tags = {t.lower() for t in match.tags}
    if tags & {"info", "packer", "suspicious", "capability"}:
        return "medium" if "suspicious" in tags else "info"
    return "high"


class YaraAnalyzer(Analyzer):
    name = "yara"
    kinds = ()  # alle Dateien

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return yara is not None and result.kind not in ("directory",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        compiled, errors = compile_rules(ctx.settings.yara_rules_dir)
        if errors and ctx.depth == 0:
            result.errors.append(f"{len(errors)} YARA-Regeldatei(en) fehlerhaft, z. B. {clip(errors[0], 200)}")
        rows = []
        for fname, rules in compiled:
            try:
                matches = rules.match(data=ctx.data, timeout=60)
            except yara.Error as exc:
                result.errors.append(f"YARA ({fname}): {exc}")
                continue
            for m in matches:
                meta = m.meta or {}
                desc = str(meta.get("description", ""))
                family = str(meta.get("malware_family", meta.get("family", "")))
                rows.append([m.rule, ", ".join(m.tags), clip(desc, 200), fname])
                label = family or m.rule
                if label not in result.detections:
                    result.detections.append(label)
                result.find(severity_for(m), f"YARA: {m.rule}", desc or f"Regel aus {fname}")
        if rows:
            result.tools.append("yara")
            result.add(Section("YARA-Treffer", table=Table(["Regel", "Tags", "Beschreibung", "Datei"], rows), llm_priority=0))
