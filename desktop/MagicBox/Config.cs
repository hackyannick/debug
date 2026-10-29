using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace MagicBox.Desktop
{
    /// <summary>Einstellungen der Desktop-App (%APPDATA%\MagicBox\desktop.json).
    /// Das API-Token liegt mit DPAPI verschlüsselt darin (nur dieser Windows-Benutzer kann es lesen).</summary>
    public sealed class Config
    {
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("MagicBox.Desktop.Token.v1");

        public string ServerUrl = "";
        public string Token = "";
        public string UserName = "";
        public string Profile = "malware";
        public bool TaskPaneVisible = true;
        public int NavWidth = 300;
        public int TaskPaneWidth = 270;
        public string WindowBounds = "";
        public bool Maximized;

        public static string Folder =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MagicBox");

        public static string FilePath => Path.Combine(Folder, "desktop.json");

        public static Config Load()
        {
            var c = new Config();
            try
            {
                if (File.Exists(FilePath))
                {
                    var d = (Dictionary<string, object>)Json.Parse(File.ReadAllText(FilePath, Encoding.UTF8));
                    c.ServerUrl = d.Str("server_url");
                    c.UserName = d.Str("user_name");
                    c.Profile = d.Str("profile", "malware");
                    c.TaskPaneVisible = d.Get("task_pane") is bool b ? b : true;
                    c.NavWidth = d.Int("nav_width", 300);
                    c.TaskPaneWidth = d.Int("task_pane_width", 270);
                    c.WindowBounds = d.Str("window");
                    c.Maximized = d.Bool("maximized");
                    c.Token = Unprotect(d.Str("token"));
                }
            }
            catch (Exception)
            {
                // beschädigte Datei: mit Vorgaben weitermachen
            }
            if (string.IsNullOrWhiteSpace(c.ServerUrl)) c.ServerUrl = InstallerDefault();
            return c;
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Folder);
                var d = new Dictionary<string, object>
                {
                    ["server_url"] = ServerUrl,
                    ["user_name"] = UserName,
                    ["profile"] = Profile,
                    ["task_pane"] = TaskPaneVisible,
                    ["nav_width"] = NavWidth,
                    ["task_pane_width"] = TaskPaneWidth,
                    ["window"] = WindowBounds,
                    ["maximized"] = Maximized,
                    ["token"] = Protect(Token),
                };
                var tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, Json.Serialize(d), new UTF8Encoding(false));
                if (File.Exists(FilePath)) File.Delete(FilePath);
                File.Move(tmp, FilePath);
            }
            catch (Exception)
            {
                // Speichern ist Komfort – die App läuft auch ohne
            }
        }

        /// <summary>Vom Installer geschriebene Vorgabe (magicbox-defaults.json neben MagicBox.exe).</summary>
        public static string InstallerDefault()
        {
            try
            {
                var file = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath) ?? ".", "magicbox-defaults.json");
                if (!File.Exists(file)) return "";
                var d = (Dictionary<string, object>)Json.Parse(File.ReadAllText(file, Encoding.UTF8));
                return d.Str("server_url").Trim();
            }
            catch (Exception)
            {
                return "";
            }
        }

        static string Protect(string token)
        {
            if (string.IsNullOrEmpty(token)) return "";
            try
            {
                var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), Entropy, DataProtectionScope.CurrentUser);
                return "dpapi:" + Convert.ToBase64String(data);
            }
            catch (Exception)
            {
                return ""; // lieber neu anmelden als das Token im Klartext ablegen
            }
        }

        static string Unprotect(string stored)
        {
            if (string.IsNullOrEmpty(stored) || !stored.StartsWith("dpapi:")) return "";
            try
            {
                var data = ProtectedData.Unprotect(Convert.FromBase64String(stored.Substring(6)), Entropy,
                    DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(data);
            }
            catch (Exception)
            {
                return "";
            }
        }
    }
}
