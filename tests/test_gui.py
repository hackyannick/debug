"""Rauchtest der Oberfläche (offscreen) – wird übersprungen, wenn PySide6/Qt nicht verfügbar ist."""

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from magicbox.config import Settings  # noqa: E402
from samples import tiny_pe64  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def test_gui_runs_job(app, tmp_path, fake_llm):
    from magicbox.gui.main_window import MainWindow
    from magicbox.gui.settings_dialog import SettingsDialog

    exe = tmp_path / "demo.exe"
    exe.write_bytes(tiny_pe64())
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path / "out"), use_radare2=False)
    win = MainWindow(s)
    win.add_paths([exe])
    deadline = time.time() + 30
    while (win.worker is not None or win.queue) and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    job = next(iter(win.jobs.values()))
    assert job.status == "fertig", job.error
    assert "Analysebericht: demo.exe" in win.doc_view.toPlainText()
    assert "Kurzfassung" in win.ai_view.toPlainText()

    dlg = SettingsDialog(s, win)
    dlg.model.setCurrentText("qwen3-coder:30b")
    assert dlg.result_settings().model == "qwen3-coder:30b"
    win.close()
