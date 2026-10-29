/*
  Mitgelieferte Basisregeln der Magic Box (generische Verhaltensindikatoren, keine Familien-Signaturen).
  Für Familienerkennung zusätzlich Community-Regeln (z. B. YARA-Forge) in den Einstellungen einbinden.
  Meta "severity": info | low | medium | high
*/

rule MB_Packer_UPX : packer
{
    meta:
        description = "Mit UPX gepackt"
        severity = "info"
    strings:
        $a = "UPX0"
        $b = "UPX1"
        $c = "UPX!"
    condition:
        2 of them and filesize < 200MB
}

rule MB_Embedded_PE : suspicious
{
    meta:
        description = "Enthält eine eingebettete Windows-Programmdatei (Dropper/Loader?)"
        severity = "medium"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        (uint16(0) != 0x5A4D and $dos) or (uint16(0) == 0x5A4D and #dos > 1)
}

rule MB_PowerShell_Cradle : suspicious
{
    meta:
        description = "PowerShell-Download/Ausführungs-Muster (Download-Cradle, kodierte Befehle, versteckte Fenster)"
        severity = "high"
    strings:
        // ganze Aufrufketten statt Einzelwörter – "DownloadFile" oder "IEX" allein stehen auch in Browsern
        $cradle1 = /(iex|invoke-expression)[\s(]{1,4}(new-object\s+)?(system\.)?net\.webclient\)?\.download(string|file|data)/ ascii wide nocase
        $cradle2 = /\.download(string|data)\s*\([^)]{1,300}\)\s*\)?\s*\|\s*(iex|invoke-expression)/ ascii wide nocase
        $cradle3 = /(iwr|invoke-webrequest|irm|invoke-restmethod)\s[^|\n]{1,300}\|\s*(iex|invoke-expression)/ ascii wide nocase
        $enc = /powershell(\.exe)?\s[^\n]{0,80}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $hidden = /powershell(\.exe)?\s[^\n]{0,80}-w(in|indowstyle)?\s+hidden/ ascii wide nocase
    condition:
        any of them
}

rule MB_Ransom_Note : suspicious
{
    meta:
        description = "Typische Formulierungen einer Erpresser-Nachricht (Ransomware)"
        severity = "high"
    strings:
        // eindeutige Erpresser-Sätze – einzelne Wörter wie "decrypt" oder "private key" stehen in jeder Krypto-Bibliothek
        $n1 = "files have been encrypted" ascii wide nocase
        $n2 = "files are encrypted" ascii wide nocase
        $n3 = "Dateien wurden verschlüsselt" ascii wide nocase
        $n4 = "to decrypt your files" ascii wide nocase
        $n5 = "pay the ransom" ascii wide nocase
        $s1 = "bitcoin" ascii wide nocase
        $s2 = ".onion" ascii wide nocase
        $s3 = "ransom" ascii wide nocase
        $s4 = "decryptor" ascii wide nocase
        $s5 = "tor browser" ascii wide nocase
    condition:
        1 of ($n*) and 1 of ($s*)
}

rule MB_Shadow_Copy_Deletion : suspicious
{
    meta:
        description = "Löscht Schattenkopien oder deaktiviert die Wiederherstellung (typisch für Ransomware)"
        severity = "high"
    strings:
        $a = "delete shadows" ascii wide nocase
        $b = "shadowcopy delete" ascii wide nocase
        $c = "recoveryenabled no" ascii wide nocase
        $d = "wbadmin delete catalog" ascii wide nocase
        $e = "resize shadowstorage" ascii wide nocase
    condition:
        any of them
}

rule MB_Credential_Theft_Browser : suspicious
{
    meta:
        description = "Greift auf gespeicherte Browser-Zugangsdaten, Cookies oder Krypto-Wallets zu (Infostealer-Verhalten)"
        severity = "high"
    strings:
        // Profilpfade fremder Browser – Chromium/Electron-Programme enthalten "Login Data", "Local State" usw. selbst
        $p1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $p2 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $p3 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $p4 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $p5 = "\\Opera Software\\Opera Stable" ascii wide nocase
        $p6 = "\\Yandex\\YandexBrowser\\User Data" ascii wide nocase
        $f1 = "Login Data" ascii wide
        $f2 = "logins.json" ascii wide
        $f3 = "key4.db" ascii wide
        $f4 = "wallet.dat" ascii wide
        $f5 = "encrypted_key" ascii wide
        $f6 = "Web Data" ascii wide
    condition:
        2 of ($p*) or (1 of ($p*) and 2 of ($f*))
}

rule MB_Anti_VM : suspicious
{
    meta:
        description = "Prüft auf virtuelle Maschinen oder Sandboxes (erschwert Analyse)"
        severity = "medium"
    strings:
        // konkrete Gast-/Sandbox-Artefakte; bloße Herstellernamen (VMware, QEMU, VirtualBox) stehen z. B. in
        // GPU-Treiberlisten von Chromium und zählen nur zusammen mit einem Artefakt
        $s1 = "VBoxService" ascii wide nocase
        $s2 = "vmtoolsd" ascii wide nocase
        $s3 = "SbieDll.dll" ascii wide nocase
        $s4 = "wine_get_unix_file_name" ascii wide
        $s5 = "cuckoomon" ascii wide nocase
        $s6 = "VBoxGuest" ascii wide nocase
        $s7 = "vboxhook.dll" ascii wide nocase
        $s8 = "HARDWARE\\ACPI\\DSDT\\VBOX__" ascii wide nocase
        $s9 = "vmGuestLib.dll" ascii wide nocase
        $g1 = "VMware" ascii wide
        $g2 = "QEMU" ascii wide
        $g3 = "VirtualBox" ascii wide
    condition:
        2 of ($s*) or (1 of ($s*) and 1 of ($g*))
}

rule MB_Exfil_Messenger_API : suspicious
{
    meta:
        description = "Nutzt Telegram- oder Discord-APIs (häufiger Exfiltrationskanal von Stealern/RATs)"
        severity = "high"
    strings:
        $a = "api.telegram.org/bot" ascii wide nocase
        $b = "discord.com/api/webhooks" ascii wide nocase
        $c = "discordapp.com/api/webhooks" ascii wide nocase
    condition:
        any of them
}

rule MB_Persistence_Run_Key : suspicious
{
    meta:
        description = "Referenziert Autostart-Registry-Schlüssel (Persistenz)"
        severity = "medium"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $b = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $c = "schtasks /create" ascii wide nocase
    condition:
        any of them
}
