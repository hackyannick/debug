"""Einordnung importierter Funktionen in verständliche Fähigkeits-Kategorien."""

from __future__ import annotations

# Kategorie -> (Severity, Erklärung, Schlüsselwörter (Präfix-Match, case-insensitive))
CAPABILITIES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "Netzwerk": ("info", "Baut Netzwerkverbindungen auf oder lädt Daten herunter.", (
        "socket", "connect", "send", "recv", "wsastartup", "internetopen", "internetconnect",
        "httpsendrequest", "httpopenrequest", "urldownloadtofile", "winhttp", "getaddrinfo",
        "gethostbyname", "curl_easy", "inet_", "bind", "listen", "accept")),
    "Prozesse starten": ("low", "Startet andere Programme oder Befehle.", (
        "createprocess", "shellexecute", "winexec", "system", "execve", "execl", "execvp",
        "popen", "fork", "posix_spawn")),
    "Code-Injektion": ("high", "Kann Code in fremde Prozesse schreiben/ausführen (typisch für Malware, aber auch Debugger/Cheats).", (
        "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc",
        "virtualallocex", "setwindowshookex", "ptrace", "rtlcreateuserthread", "ntmapviewofsection")),
    "Speicher ausführbar machen": ("medium", "Reserviert ausführbaren Speicher – typisch für Packer, JITs oder Shellcode.", (
        "virtualalloc", "virtualprotect", "mprotect", "mmap", "ntallocatevirtualmemory")),
    "Dynamisches Laden": ("low", "Lädt Bibliotheken/Funktionen zur Laufzeit (verschleiert ggf. die echten Imports).", (
        "loadlibrary", "getprocaddress", "dlopen", "dlsym", "ldrloaddll")),
    "Registry": ("low", "Liest oder schreibt die Windows-Registry.", (
        "regopenkey", "regsetvalue", "regcreatekey", "regqueryvalue", "regdeletekey", "regenumkey")),
    "Dateisystem": ("info", "Liest, schreibt oder löscht Dateien.", (
        "createfile", "writefile", "readfile", "deletefile", "movefile", "copyfile", "findfirstfile",
        "fopen", "fwrite", "unlink", "rename", "opendir", "readdir")),
    "Kryptografie": ("info", "Nutzt Verschlüsselung/Hashing.", (
        "crypt", "bcrypt", "ncrypt", "evp_", "aes_", "rsa_", "sha256", "md5_", "ssl_", "tls_")),
    "Rechte & Tokens": ("medium", "Ändert Berechtigungen oder Sicherheitstokens.", (
        "adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue", "impersonate",
        "setuid", "setgid", "seteuid", "logonuser")),
    "Dienste/Autostart": ("medium", "Richtet Dienste oder Autostart ein.", (
        "createservice", "openscmanager", "startservice", "changeserviceconfig")),
    # IsDebuggerPresent importiert auch die normale MSVC-Laufzeit – daher nur "low"
    "Anti-Debugging": ("low", "Prüft, ob ein Debugger aktiv ist (erschwert Analyse; teils auch normale Laufzeitbibliothek).", (
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "ntsetinformationthread")),
    "Tastatur/Bildschirm": ("medium", "Liest Tastatureingaben oder Bildschirminhalte.", (
        "getasynckeystate", "getkeystate", "getkeyboardstate", "bitblt", "getdc", "printwindow",
        "setclipboarddata", "getclipboarddata")),
    "Systeminformationen": ("info", "Fragt Informationen über System/Benutzer ab.", (
        "getcomputername", "getusername", "getsysteminfo", "getversion", "uname", "gethostname",
        "getenv", "getenvironmentvariable")),
}


def categorize(function_names: list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for fn in function_names:
        low = fn.lower().lstrip("_")
        for cat, (_, _, keys) in CAPABILITIES.items():
            if any(low.startswith(k) for k in keys):
                lst = found.setdefault(cat, [])
                if fn not in lst:
                    lst.append(fn)
    return found
