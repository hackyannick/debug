"""Auftragsverwaltung: Proben speichern, Warteschlange abarbeiten, Live-Ereignisse verteilen."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import BinaryIO

from magicbox.config import Settings
from magicbox.engine import Cancelled
from magicbox.pipeline import Callbacks, run
from magicbox.report.builder import safe_name

JOB_ID_RE = re.compile(r"^[0-9a-f]{12}$")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
VERDICT_RE = re.compile(r"Einstufung:\s*\**\s*([A-Za-zäöüÄÖÜ]+)", re.I)


@dataclass
class Job:
    id: str
    name: str
    sample: str
    size: int
    sha256: str
    created: float
    profile: str = "malware"
    password: str = ""
    status: str = "queued"  # queued | running | done | error | cancelled
    stage: str = "wartet"
    progress: int = 0
    started: float | None = None
    finished: float | None = None
    error: str = ""
    llm_error: str = ""
    model: str = ""
    description: str = ""
    risk: str = ""  # hoch | mittel | gering
    counts: dict = field(default_factory=dict)
    detections: list[str] = field(default_factory=list)
    llm_verdict: str = ""
    ioc_count: int = 0

    def public(self) -> dict:
        d = asdict(self)
        d.pop("password", None)
        d.pop("sample", None)
        return d


class EventHub:
    """Verteilt Ereignisse an alle verbundenen Browser (Server-Sent Events)."""

    def __init__(self):
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=5000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:  # langsamer Client – Ereignis verwerfen statt Server zu blockieren
                pass


class JobManager:
    def __init__(self, settings: Settings, data_dir: Path | None = None):
        self.settings = settings
        self.root = Path(data_dir or settings.data_dir).expanduser()
        self.jobs_dir = self.root / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.hub = EventHub()
        self.jobs: dict[str, Job] = {}
        self.live: dict[str, list[str]] = {}  # KI-Ausgabe des laufenden Jobs
        self._queue: queue.Queue[str] = queue.Queue()
        self._lock = threading.RLock()
        self._cancel: dict[str, threading.Event] = {}
        self._stop = threading.Event()
        self._load()
        self._worker = threading.Thread(target=self._loop, name="magicbox-worker", daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------ Persistenz
    def job_dir(self, job_id: str) -> Path:
        if not JOB_ID_RE.match(job_id):
            raise KeyError(job_id)
        return self.jobs_dir / job_id

    def _save(self, job: Job) -> None:
        path = self.job_dir(job.id) / "job.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(job), ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    def _load(self) -> None:
        for d in sorted(self.jobs_dir.iterdir()) if self.jobs_dir.exists() else []:
            try:
                job = Job(**json.loads((d / "job.json").read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError):
                continue
            if job.status == "running":
                job.status, job.error, job.stage = "error", "Server wurde während der Analyse neu gestartet.", "abgebrochen"
                self._save_quiet(job)
            self.jobs[job.id] = job
            if job.status == "queued":
                self._queue.put(job.id)

    def _save_quiet(self, job: Job) -> None:
        try:
            self._save(job)
        except OSError:
            pass

    # ------------------------------------------------------------------ API
    def list(self) -> list[dict]:
        with self._lock:
            return [j.public() for j in sorted(self.jobs.values(), key=lambda j: j.created, reverse=True)]

    def get(self, job_id: str) -> Job:
        with self._lock:
            return self.jobs[job_id]

    def create(self, name: str, stream: BinaryIO, size: int, password: str = "", profile: str = "") -> Job:
        job_id = uuid.uuid4().hex[:12]
        d = self.job_dir(job_id)
        (d / "sample").mkdir(parents=True)
        fname = safe_name(os.path.basename(name.replace("\\", "/"))) or "probe"
        target = d / "sample" / fname
        h = hashlib.sha256()
        remaining = size
        with open(target, "wb") as f:
            while remaining > 0:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                f.write(chunk)
                h.update(chunk)
                remaining -= len(chunk)
        if remaining:
            shutil.rmtree(d, ignore_errors=True)
            raise ValueError("Upload unvollständig")
        os.chmod(target, 0o400)  # nie ausführbar
        job = Job(id=job_id, name=os.path.basename(name.replace("\\", "/")) or fname, sample=fname, size=size,
                  sha256=h.hexdigest(), created=time.time(), profile=profile or self.settings.profile,
                  password=password)
        with self._lock:
            self.jobs[job_id] = job
            self._save(job)
        self.hub.publish({"type": "job", "job": job.public()})
        self._queue.put(job_id)
        return job

    def create_from_file(self, path: Path, profile: str = "") -> Job:
        with open(path, "rb") as f:
            return self.create(path.name, f, path.stat().st_size, profile=profile)

    def cancel(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs[job_id]
            if job.status == "queued":
                self._finish(job, "cancelled", "Abgebrochen")
            elif job.status == "running" and job_id in self._cancel:
                self._cancel[job_id].set()

    def rerun(self, job_id: str) -> Job:
        with self._lock:
            job = self.jobs[job_id]
            if job.status in ("queued", "running"):
                return job
            shutil.rmtree(self.job_dir(job_id) / "report", ignore_errors=True)
            for f in ("log.txt", "ki.txt"):
                (self.job_dir(job_id) / f).unlink(missing_ok=True)
            job = replace(job, status="queued", stage="wartet", progress=0, error="", llm_error="", started=None,
                          finished=None, risk="", counts={}, detections=[], llm_verdict="", ioc_count=0)
            self.jobs[job_id] = job
            self._save(job)
        self.hub.publish({"type": "job", "job": job.public()})
        self._queue.put(job_id)
        return job

    def delete(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs[job_id]
            if job.status == "running":
                raise RuntimeError("Läuft noch – erst abbrechen.")
            del self.jobs[job_id]
            shutil.rmtree(self.job_dir(job_id), ignore_errors=True)
        self.hub.publish({"type": "deleted", "id": job_id})

    def log_lines(self, job_id: str, limit: int = 2000) -> list[str]:
        try:
            lines = (self.job_dir(job_id) / "log.txt").read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return lines[-limit:]

    def ai_text(self, job_id: str) -> str:
        if job_id in self.live:
            return "".join(self.live[job_id])
        try:
            return (self.job_dir(job_id) / "ki.txt").read_text(encoding="utf-8")
        except OSError:
            return ""

    def stop(self) -> None:
        self._stop.set()
        for ev in self._cancel.values():
            ev.set()
        self._queue.put("")

    # ------------------------------------------------------------------ Worker
    def _loop(self) -> None:
        while not self._stop.is_set():
            job_id = self._queue.get()
            if not job_id or self._stop.is_set():
                continue
            with self._lock:
                job = self.jobs.get(job_id)
                if job is None or job.status != "queued":
                    continue
                job.status, job.started, job.stage = "running", time.time(), "Start"
                self._cancel[job_id] = threading.Event()
                self._save(job)
            self.hub.publish({"type": "job", "job": job.public()})
            try:
                self._run(job)
            except Exception:  # noqa: BLE001 – der Worker darf nie sterben
                self._finish(job, "error", traceback.format_exc(limit=3).strip().splitlines()[-1])
            finally:
                self._cancel.pop(job_id, None)
                self.live.pop(job_id, None)

    def _run(self, job: Job) -> None:
        d = self.job_dir(job.id)
        settings = replace(self.settings, profile=job.profile or self.settings.profile)
        if job.password:
            settings.archive_passwords = [job.password] + [p for p in settings.archive_passwords if p != job.password]
        cancel = self._cancel[job.id]
        log_file = open(d / "log.txt", "a", encoding="utf-8")
        self.live[job.id] = []
        pending: list[str] = []
        last_flush = [time.monotonic()]

        def flush_tokens():
            if pending:
                text = "".join(pending)
                pending.clear()
                self.hub.publish({"type": "token", "id": job.id, "text": text})
            last_flush[0] = time.monotonic()

        def on_token(t: str):
            self.live[job.id].append(t)
            pending.append(t)
            if time.monotonic() - last_flush[0] > 0.15:
                flush_tokens()

        def on_log(msg: str):
            log_file.write(msg + "\n")
            log_file.flush()
            self.hub.publish({"type": "log", "id": job.id, "line": msg})

        def on_progress(pct: int, stage: str):
            flush_tokens()
            with self._lock:
                job.progress, job.stage = pct, stage
                self._save(job)
            self.hub.publish({"type": "job", "job": job.public()})

        cb = Callbacks(log=on_log, progress=on_progress, token=on_token, is_cancelled=cancel.is_set)
        try:
            outcome = run(d / "sample" / job.sample, settings, cb, report_folder=d / "report")
        except Cancelled:
            flush_tokens()
            self._finish(job, "cancelled", "Abgebrochen")
            return
        finally:
            log_file.close()
            (d / "ki.txt").write_text("".join(self.live.get(job.id, [])), encoding="utf-8")
        flush_tokens()
        r = outcome.result
        counts = {k: 0 for k in SEV_RANK}
        for node in r.walk():
            for f in node.findings:
                counts[f.severity] += 1
        with self._lock:
            job.description = r.description
            job.counts = counts
            job.detections = sorted({x for n in r.walk() for x in n.detections})
            job.ioc_count = sum(len(v) for n in r.walk() for v in n.iocs.values())
            job.risk = "hoch" if counts["high"] or job.detections else "mittel" if counts["medium"] else "gering"
            job.llm_error = outcome.llm_error
            job.model = r.llm_model
            m = VERDICT_RE.search(r.llm_doc or "")
            job.llm_verdict = m.group(1).lower() if m else ""
        self._finish(job, "done", "")

    def _finish(self, job: Job, status: str, error: str) -> None:
        with self._lock:
            job.status, job.error, job.finished = status, error, time.time()
            job.stage = {"done": "fertig", "cancelled": "abgebrochen"}.get(status, "Fehler")
            job.progress = 100 if status == "done" else job.progress
            self._save(job)
        self.hub.publish({"type": "job", "job": job.public()})


class FolderWatcher(threading.Thread):
    """Drop-Ordner: neue, fertig kopierte Dateien werden als Auftrag übernommen und aus dem Ordner entfernt."""

    def __init__(self, manager: JobManager, folder: Path, interval: float = 3.0):
        super().__init__(name="magicbox-watch", daemon=True)
        self.manager, self.folder, self.interval = manager, Path(folder).expanduser(), interval
        self.folder.mkdir(parents=True, exist_ok=True)
        self._seen: dict[Path, tuple[int, float]] = {}

    def run(self) -> None:
        while not self.manager._stop.is_set():
            try:
                self.scan()
            except OSError:
                pass
            time.sleep(self.interval)

    def scan(self) -> None:
        for entry in sorted(self.folder.iterdir()):
            if entry.name.startswith((".", "_")) or entry.suffix in (".part", ".crdownload", ".tmp") or not entry.is_file():
                continue
            st = entry.stat()
            sig = (st.st_size, st.st_mtime)
            if self._seen.get(entry) != sig:
                self._seen[entry] = sig
                continue
            self.manager.create_from_file(entry)
            entry.unlink()
            self._seen.pop(entry, None)
