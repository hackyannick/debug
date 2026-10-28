"""capa (Mandiant): erkennt Fähigkeiten in PE/ELF/.NET und ordnet sie MITRE ATT&CK und MBC zu."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from magicbox import tools
from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip

HIGH_NAMESPACES = ("anti-analysis", "persistence", "collection/keylog", "collection/screenshot", "impact",
                   "host-interaction/process/inject", "linking/runtime-linking", "load-code/shellcode",
                   "data-manipulation/encryption", "communication/c2")
MEDIUM_NAMESPACES = ("collection", "host-interaction/process/create", "communication", "host-interaction/registry",
                     "host-interaction/service", "executable/resource", "load-code")


def parse_capa(report: dict) -> tuple[list[list[str]], dict[str, list[str]]]:
    """Gibt (Tabellenzeilen, ATT&CK-ID -> Regeln) zurück."""
    rows, attack = [], {}
    for name, rule in sorted(report.get("rules", {}).items(), key=lambda kv: kv[1]["meta"].get("namespace", "")):
        meta = rule.get("meta", {})
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        techniques = []
        for a in meta.get("attack", []) or []:
            label = f"{a.get('id', '')} {a.get('technique', '')}".strip()
            if a.get("subtechnique"):
                label += f" / {a['subtechnique']}"
            techniques.append(label)
            attack.setdefault(f"{a.get('tactic', '?')}: {label}", []).append(name)
        rows.append([name, meta.get("namespace", ""), ", ".join(techniques), str(len(rule.get("matches", [])))])
    return rows, attack


MAX_RUNS_PER_JOB = 5  # capa braucht pro Datei Sekunden bis Minuten


class CapaAnalyzer(Analyzer):
    name = "capa"
    kinds = ("pe", "elf")

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return super().matches(ctx, result) and ctx.settings.use_capa and tools.which(ctx.settings.capa_path) is not None

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        s = ctx.settings
        runs = ctx.shared.get("capa_runs", 0)
        if runs >= MAX_RUNS_PER_JOB:
            result.find("info", "capa übersprungen", f"Pro Auftrag laufen höchstens {MAX_RUNS_PER_JOB} capa-Analysen.")
            return
        ctx.shared["capa_runs"] = runs + 1
        cmd = [tools.which(s.capa_path), "-j"]
        if s.capa_rules:
            cmd += ["-r", os.path.expanduser(s.capa_rules)]
        fd, tmp = tempfile.mkstemp(prefix="magicbox_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(ctx.data)
            proc = tools.run(cmd + [tmp], timeout=s.capa_timeout_s)
        except subprocess.TimeoutExpired:
            result.errors.append(f"capa: Zeitlimit ({s.capa_timeout_s} s) überschritten")
            return
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            err = clip(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "keine Ausgabe", 300)
            result.errors.append(f"capa fehlgeschlagen: {err}")
            return
        result.tools.append("capa")
        rows, attack = parse_capa(report)
        if not rows:
            result.add(Section("Fähigkeiten (capa)", text="capa hat keine bekannten Fähigkeiten erkannt.", llm_priority=1))
            return
        result.add(Section(f"Fähigkeiten (capa, {len(rows)} Regeln)",
                           table=Table(["Fähigkeit", "Namespace", "MITRE ATT&CK", "Treffer"], rows), llm_priority=0))
        if attack:
            result.add(Section("MITRE ATT&CK-Techniken",
                               table=Table(["Taktik: Technik", "Belegt durch"],
                                           [[k, clip(", ".join(v), 300)] for k, v in sorted(attack.items())]),
                               llm_priority=0))
        for name, ns, _, _ in rows:
            if ns.startswith(HIGH_NAMESPACES):
                result.find("high", f"capa: {name}", f"Namespace {ns}")
            elif ns.startswith(MEDIUM_NAMESPACES):
                result.find("medium", f"capa: {name}", f"Namespace {ns}")
