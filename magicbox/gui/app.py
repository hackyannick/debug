"""Startpunkt der Desktop-Anwendung."""

from __future__ import annotations

import sys


STYLE = """
QMainWindow, QWidget { font-size: 10.5pt; }
#DropZone { border: 3px dashed #a78bfa; border-radius: 18px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f5f3ff, stop:1 #ede9fe); }
#DropZone[hover="true"] { border-color: #6d28d9; background: #ddd6fe; }
#SectionTitle { font-weight: 600; color: #5b21b6; margin-top: 6px; }
#LlmLabel { color: #4b5563; padding: 6px; background: #f3f4f6; border-radius: 8px; }
QPushButton { padding: 6px 12px; border-radius: 8px; border: 1px solid #c4b5fd; background: #faf5ff; }
QPushButton:hover { background: #ede9fe; }
QPushButton:disabled { color: #9ca3af; border-color: #e5e7eb; background: #f9fafb; }
QProgressBar { border: none; background: #ede9fe; border-radius: 4px; }
QProgressBar::chunk { background: #7c3aed; border-radius: 4px; }
QListWidget { border: 1px solid #e5e7eb; border-radius: 8px; padding: 4px; }
QListWidget::item { padding: 6px; }
QListWidget::item:selected { background: #ede9fe; color: #1f2937; }
QTabWidget::pane { border: 1px solid #e5e7eb; border-radius: 8px; }
QTextBrowser, QPlainTextEdit { border: none; padding: 10px; }
"""


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 fehlt. Installieren mit:  pip install PySide6", file=sys.stderr)
        return 1

    from magicbox.config import Settings
    from magicbox.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Magic Box")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    # Helle Palette erzwingen, damit das Stylesheet auch im Dark-Mode des Systems lesbar bleibt
    from PySide6.QtGui import QColor, QPalette

    pal = QPalette()
    for role, color in ((QPalette.Window, "#ffffff"), (QPalette.Base, "#ffffff"), (QPalette.Text, "#1f2937"),
                        (QPalette.WindowText, "#1f2937"), (QPalette.Button, "#faf5ff"),
                        (QPalette.ButtonText, "#1f2937"), (QPalette.Highlight, "#7c3aed"),
                        (QPalette.HighlightedText, "#ffffff"), (QPalette.AlternateBase, "#f9fafb"),
                        (QPalette.ToolTipBase, "#ffffff"), (QPalette.ToolTipText, "#1f2937")):
        pal.setColor(role, QColor(color))
    app.setPalette(pal)

    win = MainWindow(Settings.load())
    win.show()
    if len(sys.argv) > 1:
        from pathlib import Path
        win.add_paths([Path(a) for a in sys.argv[1:] if Path(a).exists()])
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
