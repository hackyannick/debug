"""Desktop-App: natives Fenster um die Web-Oberfläche (eingebettetes Chromium über Qt WebEngine).

Wie bei Spotify & Co. ist die Oberfläche eine Web-App. Die Desktop-App
* verbindet sich mit einem Magic-Box-Server (z. B. auf dem R640) – oder
* startet, wenn keiner eingestellt ist, einen eigenen Server lokal im Hintergrund.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import replace
from pathlib import Path

ICON_SVG = (b"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' "
            b"fill='#6d28d9'/><text x='32' y='45' font-size='38' text-anchor='middle'>\xf0\x9f\xaa\x84</text></svg>")


def main(argv: list[str] | None = None, server_url: str | None = None) -> int:
    # Chromium im Container/als root braucht teils --no-sandbox; für normale Desktops nicht nötig
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox")
    try:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QAction, QDesktopServices, QIcon, QPixmap
        from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMainWindow, QMessageBox
    except ImportError as exc:
        print(f"PySide6 (mit WebEngine) fehlt: {exc}\nInstallieren mit:  pip install PySide6\n"
              "Alternativ:  magicbox server  und im Browser http://127.0.0.1:8765 öffnen.", file=sys.stderr)
        return 1

    from magicbox import __version__
    from magicbox.config import Settings

    settings = Settings.load()
    url = (server_url if server_url is not None else settings.server_url).strip()
    embedded = None
    if not url:
        from magicbox.server import MagicBoxServer

        # Eingebetteter Server nur auf localhost, geschützt durch einen zufälligen Einmal-Schlüssel
        local = replace(settings, auth_mode="token")
        embedded = MagicBoxServer(local, host="127.0.0.1", port=0, token=secrets.token_urlsafe(24))
        embedded.start_background()
        start_url = f"{embedded.url}/?token={embedded.token}"
        where = "lokal (eingebauter Server)"
    else:
        start_url = url if "://" in url else f"http://{url}"
        where = start_url

    app = QApplication(sys.argv[:1] + (argv or []))
    app.setApplicationName("Magic Box")
    pix = QPixmap()
    pix.loadFromData(ICON_SVG, "SVG")
    app.setWindowIcon(QIcon(pix))

    base = QUrl(start_url)
    app_hosts = {(base.host(), base.port())}
    profile = QWebEngineProfile("magicbox")  # eigenes, persistentes Profil (Cookie für den Login bleibt erhalten)

    class Page(QWebEnginePage):
        def __init__(self, prof, parent=None):
            super().__init__(prof, parent)
            self.popups: list = []

        def createWindow(self, _type):  # „Bericht öffnen ↗“ in eigenem Fenster mit gleichem Login
            view = QWebEngineView()
            view.setPage(Page(profile, view))
            view.resize(1100, 900)
            view.setWindowTitle("Magic Box – Bericht")
            view.show()
            self.popups.append(view)
            return view.page()

        def acceptNavigationRequest(self, qurl, nav_type, is_main_frame):
            # Vom Nutzer angeklickte externe Links im System-Browser öffnen. Weiterleitungen und Formulare
            # (z. B. Ory-Login mit Captcha auf auth.example.de) bleiben im App-Fenster, damit der Login klappt.
            # Hosts, die per Weiterleitung erreicht wurden (Login-UI), gelten danach als „App-intern“.
            host = (qurl.host(), qurl.port())
            if qurl.scheme() in ("http", "https") and host not in app_hosts:
                if nav_type == QWebEnginePage.NavigationType.NavigationTypeLinkClicked:
                    QDesktopServices.openUrl(qurl)
                    return False
                app_hosts.add(host)
            return super().acceptNavigationRequest(qurl, nav_type, is_main_frame)

    def on_download(item):
        suggested = str(Path.home() / "Downloads" / item.downloadFileName())
        path, _ = QFileDialog.getSaveFileName(win, "Speichern unter", suggested)
        if path:
            item.setDownloadDirectory(str(Path(path).parent))
            item.setDownloadFileName(Path(path).name)
            item.accept()
        else:
            item.cancel()

    profile.downloadRequested.connect(on_download)

    win = QMainWindow()
    win.setWindowTitle(f"Magic Box {__version__} – {where}")
    win.resize(1400, 900)
    view = QWebEngineView(win)
    view.setPage(Page(profile, view))
    win.setCentralWidget(view)

    def change_server():
        current = settings.server_url or ""
        text, ok = QInputDialog.getText(
            win, "Server", "Adresse des Magic-Box-Servers (leer = lokal auf diesem PC):\n"
                           "z. B. http://r640:8765", text=current)
        if ok:
            settings.server_url = text.strip()
            settings.save()
            QMessageBox.information(win, "Server", "Gespeichert – wird beim nächsten Start der App verwendet.")

    menu = win.menuBar().addMenu("Magic Box")
    for label, slot, key in (("Neu laden", view.reload, "F5"), ("Server wechseln …", change_server, None),
                             ("Im Browser öffnen", lambda: QDesktopServices.openUrl(QUrl(start_url)), None),
                             ("Beenden", win.close, "Ctrl+Q")):
        act = QAction(label, win)
        if key:
            act.setShortcut(key)
        act.triggered.connect(slot)
        menu.addAction(act)

    view.load(QUrl(start_url))
    win.show()
    try:
        return app.exec()
    finally:
        if embedded is not None:
            embedded.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
