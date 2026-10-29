using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace MagicBox.Desktop
{
    static class Program
    {
        public static string Version =>
            Assembly.GetExecutingAssembly().GetName().Version is Version v ? $"{v.Major}.{v.Minor}.{v.Build}" : "?";

        static Icon icon;
        public static Icon AppIcon
        {
            get
            {
                if (icon == null)
                {
                    try { icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
                    catch (Exception) { icon = SystemIcons.Application; }
                }
                return icon;
            }
        }

        /// <summary>Öffnet eine Adresse im Standard-Browser (Windows-Shell; unter Linux/Mono xdg-open).</summary>
        public static bool OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                return true;
            }
            catch (Exception)
            {
                try
                {
                    Process.Start(new ProcessStartInfo("xdg-open", "\"" + url + "\"") { UseShellExecute = false });
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        [STAThread]
        static int Main(string[] args)
        {
            // HTTP: mehrere gleichzeitige Verbindungen (Live-Ereignisse + API + Uploads), kein „Expect: 100-continue“
            ServicePointManager.DefaultConnectionLimit = 16;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            UseModernIeEngine();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Office.Init();

            var cfg = Config.Load();
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--server" && i + 1 < args.Length) cfg.ServerUrl = ApiClient.Normalize(args[++i]);
                else if (args[i] == "--selftest" && i + 1 < args.Length) return SelfTest(args[++i], cfg);
            }
            Application.ThreadException += (s, e) =>
                MessageBox.Show(e.Exception.Message, "Magic Box – unerwarteter Fehler", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Run(new MainForm(cfg));
            return 0;
        }

        /// <summary>Das WebBrowser-Steuerelement nutzt sonst den IE7-Modus – für den Bericht IE11 (Edge-Modus) wählen.</summary>
        static void UseModernIeEngine()
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(
                           @"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"))
                    key?.SetValue(Path.GetFileName(Application.ExecutablePath), 11001, RegistryValueKind.DWord);
            }
            catch (Exception)
            {
                // nicht kritisch – der Bericht setzt zusätzlich X-UA-Compatible
            }
        }

        /// <summary>Für den Build-Test: Fenster aufbauen, JSON prüfen, Ergebnis schreiben, beenden.</summary>
        static int SelfTest(string output, Config cfg)
        {
            var result = new Dictionary<string, object> { ["version"] = Version, ["server_url"] = cfg.ServerUrl };
            int code = 0;
            try
            {
                var parsed = (Dictionary<string, object>)Json.Parse("{\"a\":[1,2.5,\"\\u00e4\\ud83d\\ude00\"],\"b\":true,\"c\":null}");
                if (parsed.List("a").Count != 3 || !parsed.Bool("b") || MainForm.CpLen((string)parsed.List("a")[2]) != 2)
                    throw new Exception("JSON-Selbsttest fehlgeschlagen");
                using (var form = new MainForm(cfg))
                {
                    form.CreateControl();
                    result["window"] = form.Text;
                }
                result["ok"] = true;
            }
            catch (Exception ex)
            {
                result["ok"] = false;
                result["error"] = ex.ToString();
                code = 1;
            }
            File.WriteAllText(output, Json.Serialize(result), new UTF8Encoding(false));
            return code;
        }
    }
}
