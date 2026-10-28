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
        $a = "DownloadString" ascii wide nocase
        $b = "DownloadFile" ascii wide nocase
        $c = "Invoke-Expression" ascii wide nocase
        $d = "IEX" ascii wide
        $e = "FromBase64String" ascii wide nocase
        $f = "-EncodedCommand" ascii wide nocase
        $g = /-(w|windowstyle)\s+hidden/ ascii wide nocase
        $h = "-nop" ascii wide nocase
        $i = "Net.WebClient" ascii wide nocase
    condition:
        3 of them
}

rule MB_Ransom_Note : suspicious
{
    meta:
        description = "Typische Formulierungen einer Erpresser-Nachricht (Ransomware)"
        severity = "high"
    strings:
        $a = "files have been encrypted" ascii wide nocase
        $b = "decrypt" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "ransom" ascii wide nocase
        $f = "private key" ascii wide nocase
        $g = "Dateien wurden verschlüsselt" ascii wide nocase
    condition:
        3 of them
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
        $a = "Login Data" ascii wide
        $b = "\\Google\\Chrome\\User Data" ascii wide nocase
        $c = "logins.json" ascii wide
        $d = "key4.db" ascii wide
        $e = "wallet.dat" ascii wide
        $f = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $g = "Web Data" ascii wide
        $h = "Local State" ascii wide
        $i = "encrypted_key" ascii wide
    condition:
        2 of them
}

rule MB_Anti_VM : suspicious
{
    meta:
        description = "Prüft auf virtuelle Maschinen oder Sandboxes (erschwert Analyse)"
        severity = "medium"
    strings:
        $a = "VBoxService" ascii wide nocase
        $b = "vmtoolsd" ascii wide nocase
        $c = "VMware" ascii wide
        $d = "SbieDll.dll" ascii wide nocase
        $e = "wine_get_unix_file_name" ascii wide
        $f = "QEMU" ascii wide
        $g = "VirtualBox" ascii wide
        $h = "cuckoomon" ascii wide nocase
    condition:
        2 of them
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
