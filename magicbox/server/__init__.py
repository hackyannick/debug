"""Magic-Box-Server: nimmt Proben per Web-Oberfläche/API entgegen, analysiert sie nacheinander und liefert Berichte."""

from .app import MagicBoxServer, serve

__all__ = ["MagicBoxServer", "serve"]
