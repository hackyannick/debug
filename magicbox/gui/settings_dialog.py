"""Einstellungsdialog: LLM-Server (R640), Modell, Sprache, Analyse-Limits."""

from __future__ import annotations

from dataclasses import replace

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from magicbox.analyzers.radare2 import find_r2
from magicbox.config import Settings
from magicbox.llm.client import LLMClient

from .workers import FuncWorker

SUGGESTED_MODELS = ["qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen3-coder:30b", "qwen3:8b", "qwen3:14b",
                    "llama3.1:8b", "mistral-nemo:12b", "deepseek-coder-v2:16b"]


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Einstellungen")
        self.setMinimumWidth(560)
        self.original = settings
        self._worker: FuncWorker | None = None

        # --- KI-Server
        self.use_llm = QCheckBox("KI-Dokumentation erzeugen")
        self.provider = QComboBox()
        self.provider.addItem("Ollama", "ollama")
        self.provider.addItem("OpenAI-kompatibel (llama.cpp, vLLM, LM Studio …)", "openai")
        self.base_url = QLineEdit()
        self.base_url.setPlaceholderText("http://r640:11434  bzw.  http://192.168.1.50:11434")
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.api_key.setPlaceholderText("optional")
        self.model = QComboBox()
        self.model.setEditable(True)
        self.model.addItems(SUGGESTED_MODELS)
        self.load_models = QPushButton("Modelle laden")
        self.test = QPushButton("Verbindung testen")
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.context = QSpinBox()
        self.context.setRange(2048, 262144)
        self.context.setSingleStep(2048)
        self.context.setSuffix(" Tokens")
        self.temperature = QDoubleSpinBox()
        self.temperature.setRange(0.0, 1.5)
        self.temperature.setSingleStep(0.1)
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 36000)
        self.timeout.setSuffix(" s")
        self.language = QComboBox()
        self.language.setEditable(True)
        self.language.addItems(["Deutsch", "Englisch", "Französisch", "Spanisch"])
        self.audience = QComboBox()
        self.audience.setEditable(True)
        self.audience.addItems(["verständlich für technisch interessierte Laien",
                                "für erfahrene Entwickler, technisch präzise",
                                "für Sicherheitsanalysten (Malware-/Incident-Response-Fokus)",
                                "für das Management: knapp, ohne Fachjargon"])

        llm_box = QGroupBox("KI-Server (z. B. Ollama auf dem PowerEdge R640)")
        f = QFormLayout(llm_box)
        f.addRow(self.use_llm)
        f.addRow("Schnittstelle", self.provider)
        f.addRow("Server-URL", self.base_url)
        f.addRow("API-Key", self.api_key)
        row = QHBoxLayout()
        row.addWidget(self.model, 1)
        row.addWidget(self.load_models)
        f.addRow("Modell", row)
        f.addRow("Kontextgröße", self.context)
        f.addRow("Temperatur", self.temperature)
        f.addRow("Zeitlimit pro Anfrage", self.timeout)
        f.addRow("Sprache der Doku", self.language)
        f.addRow("Zielgruppe", self.audience)
        f.addRow(self.test, self.status)

        # --- Analyse
        self.output_dir = QLineEdit()
        browse = QPushButton("Wählen …")
        browse.clicked.connect(self._browse)
        self.depth = QSpinBox()
        self.depth.setRange(0, 10)
        self.members = QSpinBox()
        self.members.setRange(1, 100000)
        self.functions = QSpinBox()
        self.functions.setRange(1, 200)
        self.children = QSpinBox()
        self.children.setRange(0, 200)
        self.use_r2 = QCheckBox("radare2 für Pseudocode nutzen (falls installiert)")
        self.r2_path = QLineEdit()
        self.r2_path.setPlaceholderText("r2")
        self.r2_state = QLabel()

        an_box = QGroupBox("Analyse && Ausgabe")
        g = QFormLayout(an_box)
        out_row = QHBoxLayout()
        out_row.addWidget(self.output_dir, 1)
        out_row.addWidget(browse)
        g.addRow("Berichte speichern in", out_row)
        g.addRow("Max. Archiv-Tiefe", self.depth)
        g.addRow("Max. Dateien pro Archiv/Ordner", self.members)
        g.addRow("Max. Funktionen (Disassembly)", self.functions)
        g.addRow("Max. KI-Teilanalysen", self.children)
        g.addRow(self.use_r2)
        g.addRow("radare2-Pfad", self.r2_path)
        g.addRow("", self.r2_state)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addWidget(llm_box)
        lay.addWidget(an_box)
        lay.addWidget(buttons)

        self.load_models.clicked.connect(self._load_models)
        self.test.clicked.connect(self._test)
        self.provider.currentIndexChanged.connect(self._provider_changed)
        self.r2_path.textChanged.connect(self._update_r2)
        self._fill(settings)

    # ------------------------------------------------------------------
    def _fill(self, s: Settings) -> None:
        self.use_llm.setChecked(s.use_llm)
        self.provider.setCurrentIndex(max(0, self.provider.findData(s.provider)))
        self.base_url.setText(s.base_url)
        self.api_key.setText(s.api_key)
        self.model.setCurrentText(s.model)
        self.context.setValue(s.context_tokens)
        self.temperature.setValue(s.temperature)
        self.timeout.setValue(s.timeout_s)
        self.language.setCurrentText(s.language)
        self.audience.setCurrentText(s.audience)
        self.output_dir.setText(s.output_dir)
        self.depth.setValue(s.max_archive_depth)
        self.members.setValue(s.max_archive_members)
        self.functions.setValue(s.max_disasm_functions)
        self.children.setValue(s.max_llm_children)
        self.use_r2.setChecked(s.use_radare2)
        self.r2_path.setText(s.radare2_path)
        self._update_r2()

    def result_settings(self) -> Settings:
        return replace(
            self.original,
            use_llm=self.use_llm.isChecked(), provider=self.provider.currentData(),
            base_url=self.base_url.text().strip(), api_key=self.api_key.text().strip(),
            model=self.model.currentText().strip(), context_tokens=self.context.value(),
            temperature=self.temperature.value(), timeout_s=self.timeout.value(),
            language=self.language.currentText().strip() or "Deutsch",
            audience=self.audience.currentText().strip(), output_dir=self.output_dir.text().strip(),
            max_archive_depth=self.depth.value(), max_archive_members=self.members.value(),
            max_disasm_functions=self.functions.value(), max_llm_children=self.children.value(),
            use_radare2=self.use_r2.isChecked(), radare2_path=self.r2_path.text().strip() or "r2",
        )

    def _provider_changed(self) -> None:
        url = self.base_url.text().strip()
        if self.provider.currentData() == "openai" and url.endswith(":11434"):
            self.base_url.setText(url[: -len(":11434")] + ":8080")
        elif self.provider.currentData() == "ollama" and url.endswith(":8080"):
            self.base_url.setText(url[: -len(":8080")] + ":11434")

    def _update_r2(self) -> None:
        path = find_r2(self.r2_path.text().strip() or "r2")
        self.r2_state.setText(f"✔ gefunden: {path}" if path else "✖ nicht gefunden – Analyse läuft dann ohne Pseudocode")

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Berichtsordner wählen", self.output_dir.text())
        if d:
            self.output_dir.setText(d)

    def _run(self, fn, on_done) -> None:
        if self._worker and self._worker.isRunning():
            return
        self.status.setText("⏳ Frage Server an …")
        self._worker = FuncWorker(fn)
        self._worker.done.connect(on_done)
        self._worker.error.connect(lambda e: self.status.setText(f"✖ {e}"))
        self._worker.start()

    def _load_models(self) -> None:
        client = LLMClient(self.result_settings())

        def done(models):
            current = self.model.currentText()
            self.model.clear()
            self.model.addItems(models or SUGGESTED_MODELS)
            self.model.setCurrentText(current if current in models or not models else models[0])
            self.status.setText(f"✔ {len(models)} Modell(e) gefunden.")

        self._run(client.list_models, done)

    def _test(self) -> None:
        client = LLMClient(self.result_settings())
        self._run(client.check, lambda msg: self.status.setText(f"✔ {msg}"))
