using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MagicBox.Desktop
{
    /// <summary>Grundgerüst der Dialoge: Kopfband mit Titel und Erklärung, Schaltflächen unten rechts.</summary>
    public class OfficeDialog : Form
    {
        protected readonly Panel Body = new Panel { Dock = DockStyle.Fill };
        protected readonly FlowLayoutPanel Buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false,
        };

        public OfficeDialog(string title, string description, int width, int height)
        {
            Text = title;
            Font = Office.UiFont;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(Office.S(width), Office.S(height));
            BackColor = SystemColors.Control;
            Icon = Program.AppIcon;

            var head = new GradientPanel { Dock = DockStyle.Top, Height = Office.S(54), TopColor = Color.White, BottomColor = Office.SubBottom, BottomLine = true };
            head.Controls.Add(new Label
            {
                Text = description, AutoSize = false, Font = Office.UiFont, BackColor = Color.Transparent,
                Location = new Point(Office.S(26), Office.S(26)), Size = new Size(ClientSize.Width - Office.S(36), Office.S(26)),
                Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
            });
            head.Controls.Add(new Label
            {
                Text = title, AutoSize = true, Font = Office.UiBold, BackColor = Color.Transparent,
                Location = new Point(Office.S(12), Office.S(9)), ForeColor = Office.Title,
            });
            Buttons.Padding = new Padding(Office.S(8));
            var line = new Label { Dock = DockStyle.Bottom, Height = 2, BorderStyle = BorderStyle.Fixed3D };
            Body.Padding = new Padding(Office.S(14), Office.S(12), Office.S(14), Office.S(6));
            Controls.Add(Body);
            Controls.Add(line);
            Controls.Add(Buttons);
            Controls.Add(head);
        }

        protected Button AddButton(string text, DialogResult result = DialogResult.None, EventHandler click = null)
        {
            var b = new Button
            {
                Text = text, DialogResult = result, AutoSize = true, MinimumSize = new Size(Office.S(80), Office.S(24)),
                Margin = new Padding(Office.S(6), 0, 0, 0), UseVisualStyleBackColor = true,
            };
            if (click != null) b.Click += click;
            Buttons.Controls.Add(b);
            return b;
        }
    }

    /// <summary>Server-Adresse eingeben.</summary>
    public sealed class ConnectDialog : OfficeDialog
    {
        readonly TextBox url = new TextBox();
        public string Url => ApiClient.Normalize(url.Text);

        public ConnectDialog(string current) : base("Verbindung zum Server",
            "Adresse deines Magic-Box-Servers. Die Analyse läuft dort, die App zeigt Aufträge und Berichte an.", 440, 190)
        {
            var label = new Label { Text = "&Server-Adresse:", AutoSize = true, Dock = DockStyle.Top };
            url.Text = current;
            url.Dock = DockStyle.Top;
            var hint = new Label
            {
                Text = "z. B. https://magicbox.hackdv.com oder http://r640:8765", AutoSize = true, Dock = DockStyle.Top,
                ForeColor = Office.Muted, Padding = new Padding(0, Office.S(4), 0, 0),
            };
            Body.Controls.Add(hint);
            Body.Controls.Add(url);
            Body.Controls.Add(label);
            var cancel = AddButton("Abbrechen", DialogResult.Cancel);
            var ok = AddButton("Verbinden", DialogResult.OK);
            AcceptButton = ok;
            CancelButton = cancel;
        }
    }

    /// <summary>Zugangsschlüssel (Server im Modus web_token).</summary>
    public sealed class TokenDialog : OfficeDialog
    {
        readonly TextBox key = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Top };
        public string Key => key.Text.Trim();

        public TokenDialog(string server) : base("Anmelden", $"{server} ist mit einem Zugangsschlüssel geschützt.", 420, 170)
        {
            Body.Controls.Add(key);
            Body.Controls.Add(new Label { Text = "&Zugangsschlüssel:", AutoSize = true, Dock = DockStyle.Top });
            var cancel = AddButton("Abbrechen", DialogResult.Cancel);
            AcceptButton = AddButton("Anmelden", DialogResult.OK);
            CancelButton = cancel;
        }
    }

    /// <summary>Wartet, während die Anmeldung im System-Browser läuft.</summary>
    public sealed class BrowserLoginDialog : OfficeDialog
    {
        readonly ApiClient api;
        readonly CancellationTokenSource cts = new CancellationTokenSource();
        readonly Label status = new Label { AutoSize = false, Dock = DockStyle.Top, Height = Office.S(44) };
        public Dictionary<string, object> Result { get; private set; }

        public BrowserLoginDialog(ApiClient api) : base("Anmelden",
            "Die Anmeldung läuft im Browser (Ory-Login mit Captcha und ggf. 2FA).", 440, 200)
        {
            this.api = api;
            status.Text = "Browser wurde geöffnet. Bitte dort anmelden und „Zulassen“ wählen …";
            var bar = new ProgressBar { Style = ProgressBarStyle.Marquee, Dock = DockStyle.Top, Height = Office.S(16), MarqueeAnimationSpeed = 30 };
            Body.Controls.Add(bar);
            Body.Controls.Add(status);
            CancelButton = AddButton("Abbrechen", DialogResult.Cancel, (s, e) => cts.Cancel());
            Shown += async (s, e) => await Start();
            FormClosing += (s, e) => cts.Cancel();
        }

        async Task Start()
        {
            try
            {
                Result = await DesktopLogin.Run(api, cts.Token);
                DialogResult = DialogResult.OK;
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (IsDisposed) return;
                MessageBox.Show(this, ex.Message, "Anmeldung", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                DialogResult = DialogResult.Cancel;
            }
        }
    }

    /// <summary>Einstellungen des Servers (KI, Analyse, Werkzeuge) – über GET/PUT /api/settings.</summary>
    public sealed class ServerSettingsForm : OfficeDialog
    {
        sealed class Field
        {
            public string Key, Label, Kind; // text | int | float | bool | choice | lines | password
            public string[] Choices;
            public Control Control;
        }

        readonly ApiClient api;
        readonly List<Field> fields = new List<Field>();
        readonly Label result = new Label { AutoSize = false, Dock = DockStyle.Bottom, Height = Office.S(34), ForeColor = Office.Muted };
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };

        public ServerSettingsForm(ApiClient api) : base("Server-Einstellungen",
            "Gelten für alle Benutzer des Servers ab dem nächsten Auftrag.", 560, 520)
        {
            this.api = api;
            Page("KI-Server", new[]
            {
                F("use_llm", "KI-Dokumentation erzeugen", "bool"),
                F("provider", "Schnittstelle", "choice", "ollama", "openai"),
                F("base_url", "Server-URL", "text"),
                F("model", "Modell", "model"),
                F("api_key", "API-Key", "password"),
                F("context_tokens", "Kontextgröße (Tokens)", "int"),
                F("temperature", "Temperatur", "float"),
                F("language", "Sprache", "text"),
                F("audience", "Zielgruppe", "choice", "verständlich für technisch interessierte Laien",
                  "für Sicherheitsanalysten (Malware-/Incident-Response-Fokus)", "für erfahrene Entwickler, technisch präzise",
                  "für das Management: knapp, ohne Fachjargon"),
                F("profile", "Standard-Profil", "choice", "malware", "allgemein"),
                F("max_llm_children", "Max. KI-Teilanalysen", "int"),
            });
            Page("Analyse", new[]
            {
                F("archive_passwords", "Archiv-Passwörter (eins pro Zeile)", "lines"),
                F("yara_rules_dir", "Eigene YARA-Regeln (Ordner auf dem Server)", "text"),
                F("max_archive_depth", "Max. Archiv-Tiefe", "int"),
                F("max_archive_members", "Max. Dateien pro Archiv", "int"),
                F("max_disasm_functions", "Max. Funktionen (Disassembly)", "int"),
                F("tool_timeout_s", "Zeitlimit Werkzeuge (s)", "int"),
                F("use_radare2", "radare2 nutzen (Pseudocode)", "bool"),
                F("use_capa", "capa nutzen (Fähigkeiten + MITRE ATT&CK)", "bool"),
            });
            Page("Werkzeuge", new[]
            {
                F("radare2_path", "radare2", "text"), F("capa_path", "capa", "text"), F("capa_rules", "capa-Regeln", "text"),
                F("capa_timeout_s", "capa-Zeitlimit (s)", "int"), F("upx_path", "UPX", "text"),
                F("sevenzip_path", "7-Zip", "text"), F("ilspy_path", "ilspycmd", "text"),
            });
            Body.Controls.Add(tabs);
            Body.Controls.Add(result);
            var cancel = AddButton("Abbrechen", DialogResult.Cancel);
            var save = AddButton("OK", DialogResult.None, async (s, e) => { if (await Save()) DialogResult = DialogResult.OK; });
            AddButton("KI-Verbindung testen", DialogResult.None, async (s, e) => await Check());
            AcceptButton = save;
            CancelButton = cancel;
            Shown += async (s, e) => await LoadValues();
        }

        static Field F(string key, string label, string kind, params string[] choices) =>
            new Field { Key = key, Label = label, Kind = kind, Choices = choices };

        void Page(string title, Field[] list)
        {
            var page = new TabPage(title) { UseVisualStyleBackColor = true, Padding = new Padding(Office.S(8)), AutoScroll = true };
            var grid = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2 };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            foreach (var f in list)
            {
                Control c;
                switch (f.Kind)
                {
                    case "bool":
                        c = new CheckBox { Text = f.Label, AutoSize = true };
                        grid.Controls.Add(c);
                        grid.SetColumnSpan(c, 2);
                        f.Control = c;
                        fields.Add(f);
                        continue;
                    case "choice":
                        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDown, Dock = DockStyle.Fill };
                        combo.Items.AddRange(f.Choices);
                        c = combo;
                        break;
                    case "model":
                        var model = new ComboBox { DropDownStyle = ComboBoxStyle.DropDown, Dock = DockStyle.Fill };
                        model.DropDown += async (s, e) => await LoadModels(model);
                        c = model;
                        break;
                    case "lines":
                        c = new TextBox { Multiline = true, Height = Office.S(70), ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
                        break;
                    case "password":
                        c = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill };
                        break;
                    default:
                        c = new TextBox { Dock = DockStyle.Fill };
                        break;
                }
                grid.Controls.Add(new Label { Text = f.Label + ":", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, Office.S(6), Office.S(6), 0) });
                grid.Controls.Add(c);
                f.Control = c;
                fields.Add(f);
            }
            page.Controls.Add(grid);
            tabs.TabPages.Add(page);
        }

        async Task LoadValues()
        {
            try
            {
                var d = await api.Get("/api/settings");
                foreach (var f in fields)
                {
                    var v = d.Get(f.Key);
                    if (f.Control is CheckBox cb) cb.Checked = v is bool b && b;
                    else if (f.Kind == "lines") f.Control.Text = string.Join(Environment.NewLine, d.Strings(f.Key));
                    else f.Control.Text = v is double x ? x.ToString(CultureInfo.InvariantCulture) : Convert.ToString(v, CultureInfo.InvariantCulture);
                }
            }
            catch (Exception ex)
            {
                result.ForeColor = Office.Bad;
                result.Text = "Einstellungen nicht ladbar: " + ex.Message;
            }
        }

        Dictionary<string, object> Values()
        {
            var d = new Dictionary<string, object>();
            foreach (var f in fields)
            {
                var text = f.Control.Text.Trim();
                switch (f.Kind)
                {
                    case "bool": d[f.Key] = ((CheckBox)f.Control).Checked; break;
                    case "int":
                        if (!int.TryParse(text, out var i)) throw new FormatException($"„{f.Label}“: bitte eine ganze Zahl eingeben.");
                        d[f.Key] = i;
                        break;
                    case "float":
                        if (!double.TryParse(text.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var x))
                            throw new FormatException($"„{f.Label}“: bitte eine Zahl eingeben.");
                        d[f.Key] = x;
                        break;
                    case "lines": d[f.Key] = text.Replace("\r\n", "\n"); break;
                    default: d[f.Key] = text; break;
                }
            }
            return d;
        }

        async Task<bool> Save()
        {
            try
            {
                await api.Obj(HttpMethod.Put, "/api/settings", Values());
                return true;
            }
            catch (Exception ex)
            {
                result.ForeColor = Office.Bad;
                result.Text = ex.Message;
                return false;
            }
        }

        async Task Check()
        {
            result.ForeColor = Office.Muted;
            result.Text = "Prüfe …";
            if (!await Save()) return;
            try
            {
                var r = await api.Post("/api/llm/check");
                result.ForeColor = r.Bool("ok") ? Office.Good : Office.Bad;
                result.Text = (r.Bool("ok") ? "✔ " : "✘ ") + r.Str("message");
            }
            catch (Exception ex)
            {
                result.ForeColor = Office.Bad;
                result.Text = ex.Message;
            }
        }

        async Task LoadModels(ComboBox combo)
        {
            if (combo.Items.Count > 0) return;
            try
            {
                if (!await Save()) return;
                var r = await api.Get("/api/llm/models");
                foreach (var m in r.Strings("models")) combo.Items.Add(m);
                if (r.Str("error").Length > 0) result.Text = r.Str("error");
            }
            catch (Exception ex)
            {
                result.Text = ex.Message;
            }
        }
    }

    /// <summary>Übersicht der Analyse-Werkzeuge auf dem Server.</summary>
    public sealed class ToolsForm : OfficeDialog
    {
        public ToolsForm(List<object> tools) : base("Analyse-Werkzeuge",
            "Fehlende Werkzeuge werden übersprungen – die Analyse läuft trotzdem.", 720, 420)
        {
            var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HeaderStyle = ColumnHeaderStyle.Nonclickable };
            list.Columns.Add("", Office.S(26));
            list.Columns.Add("Werkzeug", Office.S(120));
            list.Columns.Add("Wofür", Office.S(250));
            list.Columns.Add("Status / Installation", Office.S(280));
            foreach (var t in tools.OfType<Dictionary<string, object>>())
            {
                var ok = t.Str("path").Length > 0;
                var item = new ListViewItem(ok ? "✔" : "–") { ForeColor = ok ? Office.Good : Office.Muted };
                item.SubItems.Add(t.Str("name"));
                item.SubItems.Add(t.Str("purpose"));
                item.SubItems.Add(ok ? t.Str("path") : t.Str("hint"));
                item.UseItemStyleForSubItems = false;
                list.Items.Add(item);
            }
            Body.Controls.Add(list);
            AcceptButton = CancelButton = AddButton("Schließen", DialogResult.OK);
        }
    }
}
