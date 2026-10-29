using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MagicBox.Desktop
{
    /// <summary>Hauptfenster: Navigationsbereich (Aufträge) · Auftragsansicht · Aufgabenbereich (Neue Analyse).</summary>
    public sealed class MainForm : Form
    {
        readonly Config cfg;
        ApiClient api;
        EventStream events;
        Dictionary<string, object> status = new Dictionary<string, object>();
        readonly Dictionary<string, Job> jobs = new Dictionary<string, Job>();
        string current;
        readonly StringBuilder ai = new StringBuilder();
        int aiLen, logTotal;
        bool loading, connected, relogging;
        string reportKey = "";
        DateTime lastTokenAt = DateTime.MinValue, llmSince = DateTime.MinValue;
        int uploadsRunning;

        // Fensterteile
        readonly MenuStrip menu = new MenuStrip();
        readonly ToolStrip tools = new ToolStrip { GripStyle = ToolStripGripStyle.Visible, ImageScalingSize = new Size(Office.S(16), Office.S(16)) };
        readonly StatusStrip statusBar = new StatusStrip();
        readonly ToolStripStatusLabel statusText = new ToolStripStatusLabel { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        readonly ToolStripStatusLabel uploadText = new ToolStripStatusLabel { Visible = false };
        readonly ToolStripProgressBar uploadBar = new ToolStripProgressBar { Visible = false, Maximum = 100 };
        readonly ToolStripStatusLabel llmText = new ToolStripStatusLabel { BorderSides = ToolStripStatusLabelBorderSides.Left };
        readonly ToolStripStatusLabel connText = new ToolStripStatusLabel { BorderSides = ToolStripStatusLabelBorderSides.Left };
        readonly SplitContainer split1 = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        readonly SplitContainer split2 = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel2 };
        readonly PaneHeader navHeader = new PaneHeader("Aufträge");
        readonly JobList list = new JobList { Dock = DockStyle.Fill };
        readonly Panel welcome = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, AutoScroll = true };
        readonly Label welcomeText = new Label { AutoSize = false };
        readonly LinkLabel welcomeLink = new LinkLabel { AutoSize = true };
        readonly Panel jobView = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Visible = false };
        readonly PaneHeader jobHeader = new PaneHeader("");
        readonly Label meta = new Label { AutoSize = true, BackColor = Color.Transparent, ForeColor = Office.Muted, UseMnemonic = false };
        readonly LinkLabel sha = new LinkLabel { AutoSize = true, BackColor = Color.Transparent, Font = new Font("Consolas", 8f) };
        readonly FlowLayoutPanel chips = new FlowLayoutPanel { AutoSize = true, BackColor = Color.Transparent, WrapContents = true, Margin = new Padding(0) };
        readonly StepIndicator steps = new StepIndicator { Dock = DockStyle.Fill };
        readonly OfficeProgress progress = new OfficeProgress { Anchor = AnchorStyles.Left | AnchorStyles.Right };
        readonly Label pct = new Label { AutoSize = true, BackColor = Color.Transparent, Font = Office.UiBold };
        readonly Label stage = new Label { AutoSize = true, BackColor = Color.Transparent, ForeColor = Office.Muted, UseMnemonic = false };
        readonly TableLayoutPanel progressRow = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, BackColor = Color.Transparent };
        readonly TextBox askBox = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 2000 };
        readonly Button askButton = new Button { Text = "&Fragen", UseVisualStyleBackColor = true };
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
        WebBrowser browser;
        readonly TextBox reportFallback = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, BackColor = Color.White, MaxLength = 0 };
        readonly Label reportPlaceholder = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, BackColor = Color.White, ForeColor = Office.Muted };
        readonly TextBox aiBox = Mono();
        readonly TextBox logBox = Mono();
        readonly Label aiWait = new Label { Dock = DockStyle.Top, AutoSize = false, Visible = false, BackColor = Color.FromArgb(255, 255, 225), ForeColor = Color.Black, BorderStyle = BorderStyle.FixedSingle, TextAlign = ContentAlignment.MiddleLeft };

        // Aufgabenbereich
        readonly ComboBox profileBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        readonly TextBox passwordBox = new TextBox();
        readonly TextBox questionBox = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 2000 };
        readonly Label serverInfo = new Label { AutoSize = true, BackColor = Color.Transparent, UseMnemonic = false };

        // Menü-/Symbolleisten-Einträge, die vom Auftrag abhängen
        readonly List<ToolStripItem> needsJob = new List<ToolStripItem>(), needsReport = new List<ToolStripItem>(),
            needsActive = new List<ToolStripItem>(), needsIdle = new List<ToolStripItem>(), needsServer = new List<ToolStripItem>();
        ToolStripMenuItem taskPaneItem;

        static TextBox Mono() => new TextBox
        {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = Office.Mono,
            BackColor = Color.White, WordWrap = true, MaxLength = 0, BorderStyle = BorderStyle.None,
        };

        public MainForm(Config cfg)
        {
            this.cfg = cfg;
            Text = "Magic Box";
            Icon = Program.AppIcon;
            Font = Office.UiFont;
            BackColor = Office.Back;
            MinimumSize = new Size(Office.S(900), Office.S(560));
            Size = new Size(Office.S(1360), Office.S(860));
            StartPosition = FormStartPosition.CenterScreen;
            KeyPreview = true;
            ApplySavedBounds();

            menu.Font = tools.Font = statusBar.Font = Office.UiFont;
            BuildMenu();
            BuildToolbar();
            BuildStatusBar();
            BuildLayout();

            var anim = new System.Windows.Forms.Timer { Interval = 80 };
            anim.Tick += (s, e) => Animate();
            anim.Start();
            var slow = new System.Windows.Forms.Timer { Interval = 1000 };
            slow.Tick += (s, e) => UpdateAiWait();
            slow.Start();

            AllowDrop = true;
            WireDrop(this);
            Shown += async (s, e) => await Connect();
            FormClosing += (s, e) => SaveLayout();
            UpdateCommands();
        }

        // ================================================================== Aufbau
        ToolStripMenuItem Item(ToolStripMenuItem parent, string text, Action action, Keys keys = Keys.None, Image image = null,
            List<ToolStripItem> group = null)
        {
            var item = new ToolStripMenuItem(text, image, (s, e) => action()) { ShortcutKeys = keys };
            parent.DropDownItems.Add(item);
            group?.Add(item);
            return item;
        }

        void BuildMenu()
        {
            var file = new ToolStripMenuItem("&Datei");
            Item(file, "Datei &analysieren …", ChooseFiles, Keys.Control | Keys.O, Icons.Open(), needsServer);
            file.DropDownItems.Add(new ToolStripSeparator());
            Item(file, "Bericht im &Web-Browser öffnen", OpenInBrowser, Keys.None, Icons.Browser(), needsJob);
            var save = new ToolStripMenuItem("Bericht &speichern unter", Icons.Save());
            Item(save, "Bericht als &HTML …", () => SaveAs("report", "bericht.html", "HTML-Seite|*.html"), Keys.Control | Keys.S, null, needsReport);
            Item(save, "Bericht als &Markdown …", () => SaveAs("report.md", "bericht.md", "Markdown|*.md"), Keys.None, null, needsReport);
            Item(save, "&Rohdaten (JSON) …", () => SaveAs("analysis.json", "analysis.json", "JSON|*.json"), Keys.None, null, needsReport);
            Item(save, "&IOCs (CSV) …", () => SaveAs("iocs.csv", "iocs.csv", "CSV|*.csv"), Keys.None, null, needsReport);
            file.DropDownItems.Add(save);
            needsReport.Add(save);
            file.DropDownItems.Add(new ToolStripSeparator());
            Item(file, "Seite ein&richten …", () => browser?.ShowPageSetupDialog(), Keys.None, null, needsReport);
            Item(file, "Seiten&ansicht", () => browser?.ShowPrintPreviewDialog(), Keys.None, null, needsReport);
            Item(file, "&Drucken …", () => browser?.ShowPrintDialog(), Keys.Control | Keys.P, Icons.Print(), needsReport);
            file.DropDownItems.Add(new ToolStripSeparator());
            Item(file, "Ab&melden", () => _ = Logout(), Keys.None, Icons.Key(), needsServer);
            Item(file, "&Beenden", Close, Keys.Alt | Keys.F4);

            var edit = new ToolStripMenuItem("&Bearbeiten");
            Item(edit, "SHA-256 &kopieren", CopySha, Keys.Control | Keys.Shift | Keys.C, null, needsJob);
            Item(edit, "Ausgewählten Text kopieren", CopySelection, Keys.None);

            var view = new ToolStripMenuItem("&Ansicht");
            taskPaneItem = Item(view, "&Aufgabenbereich", ToggleTaskPane, Keys.Control | Keys.F1, Icons.TaskPane());
            view.DropDownItems.Add(new ToolStripSeparator());
            Item(view, "&Bericht", () => tabs.SelectedIndex = 0, Keys.Control | Keys.D1);
            Item(view, "&KI live", () => tabs.SelectedIndex = 1, Keys.Control | Keys.D2);
            Item(view, "&Protokoll", () => tabs.SelectedIndex = 2, Keys.Control | Keys.D3);
            view.DropDownItems.Add(new ToolStripSeparator());
            Item(view, "&Aktualisieren", () => _ = Reload(), Keys.F5, Icons.Refresh(), needsServer);

            var job = new ToolStripMenuItem("A&uftrag");
            Item(job, "&Frage stellen", () => { askBox.Focus(); }, Keys.Control | Keys.Q, Icons.Ask(), needsJob);
            Item(job, "&Erneut analysieren", () => _ = Rerun(), Keys.None, Icons.Rerun(), needsIdle);
            Item(job, "&Abbrechen", () => _ = CancelJob(), Keys.None, Icons.Cancel(), needsActive);
            job.DropDownItems.Add(new ToolStripSeparator());
            Item(job, "&Löschen", () => _ = DeleteJob(), Keys.None, Icons.Delete(), needsIdle);

            var extras = new ToolStripMenuItem("E&xtras");
            Item(extras, "&Server-Einstellungen …", OpenServerSettings, Keys.None, Icons.Settings(), needsServer);
            Item(extras, "&Analyse-Werkzeuge …", ShowTools, Keys.None, Icons.Tools(), needsServer);
            Item(extras, "&KI-Verbindung testen", () => _ = CheckLlm(), Keys.None, null, needsServer);
            extras.DropDownItems.Add(new ToolStripSeparator());
            Item(extras, "&Verbindung …", ChangeServer, Keys.None, Icons.Browser());

            var help = new ToolStripMenuItem("&?");
            Item(help, "&Info über Magic Box", About);

            menu.Items.AddRange(new ToolStripItem[] { file, edit, view, job, extras, help });
            MainMenuStrip = menu;
        }

        ToolStripButton Tool(string text, Image image, Action action, List<ToolStripItem> group, bool showText = false)
        {
            var b = new ToolStripButton(text, image, (s, e) => action())
            {
                DisplayStyle = showText ? ToolStripItemDisplayStyle.ImageAndText : ToolStripItemDisplayStyle.Image,
                ToolTipText = text.Replace("&", ""),
            };
            tools.Items.Add(b);
            group?.Add(b);
            return b;
        }

        void BuildToolbar()
        {
            Tool("Datei analysieren", Icons.Open(), ChooseFiles, needsServer, true);
            tools.Items.Add(new ToolStripSeparator());
            var save = new ToolStripDropDownButton("Speichern", Icons.Save()) { DisplayStyle = ToolStripItemDisplayStyle.Image, ToolTipText = "Bericht speichern unter" };
            save.DropDownItems.Add("Bericht als HTML …", null, (s, e) => SaveAs("report", "bericht.html", "HTML-Seite|*.html"));
            save.DropDownItems.Add("Bericht als Markdown …", null, (s, e) => SaveAs("report.md", "bericht.md", "Markdown|*.md"));
            save.DropDownItems.Add("Rohdaten (JSON) …", null, (s, e) => SaveAs("analysis.json", "analysis.json", "JSON|*.json"));
            save.DropDownItems.Add("IOCs (CSV) …", null, (s, e) => SaveAs("iocs.csv", "iocs.csv", "CSV|*.csv"));
            tools.Items.Add(save);
            needsReport.Add(save);
            Tool("Drucken", Icons.Print(), () => browser?.ShowPrintDialog(), needsReport);
            Tool("Im Web-Browser öffnen", Icons.Browser(), OpenInBrowser, needsJob);
            tools.Items.Add(new ToolStripSeparator());
            Tool("Frage stellen", Icons.Ask(), () => askBox.Focus(), needsJob, true);
            Tool("Erneut analysieren", Icons.Rerun(), () => _ = Rerun(), needsIdle);
            Tool("Abbrechen", Icons.Cancel(), () => _ = CancelJob(), needsActive);
            Tool("Löschen", Icons.Delete(), () => _ = DeleteJob(), needsIdle);
            tools.Items.Add(new ToolStripSeparator());
            Tool("Aktualisieren", Icons.Refresh(), () => _ = Reload(), needsServer);
            Tool("Server-Einstellungen", Icons.Settings(), OpenServerSettings, needsServer);
            Tool("Analyse-Werkzeuge", Icons.Tools(), ShowTools, needsServer);
            var pane = Tool("Aufgabenbereich", Icons.TaskPane(), ToggleTaskPane, null);
            pane.Alignment = ToolStripItemAlignment.Right;
        }

        void BuildStatusBar()
        {
            statusBar.Items.AddRange(new ToolStripItem[] { statusText, uploadText, uploadBar, llmText, connText });
            statusBar.ShowItemToolTips = true;
            llmText.Click += (s, e) => _ = CheckLlm();
        }

        void BuildLayout()
        {
            // --- Navigationsbereich links
            var nav = new FramePanel { Dock = DockStyle.Fill };
            var navInner = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
            var navOpen = new NavButton("Datei analysieren …", Icons.Open());
            navOpen.Click += (s, e) => ChooseFiles();
            var navSettings = new NavButton("Server-Einstellungen", Icons.Settings());
            navSettings.Click += (s, e) => OpenServerSettings();
            var navJobs = new NavButton("Aufträge", Icons.Report()) { Selected = true };
            navInner.Controls.Add(list);
            navInner.Controls.Add(navOpen);
            navInner.Controls.Add(navSettings);
            navInner.Controls.Add(navJobs);
            navInner.Controls.Add(navHeader);
            nav.Controls.Add(navInner);
            list.SelectedIndexChanged += (s, e) =>
            {
                var j = list.JobAt(list.SelectedIndex);
                if (j != null && j.Id != current) _ = SelectJob(j.Id, true);
            };
            list.KeyDown += (s, e) => { if (e.KeyCode == Keys.Delete) _ = DeleteJob(); };
            var listMenu = new ContextMenuStrip();
            listMenu.Items.Add("Erneut analysieren", Icons.Rerun(), (s, e) => _ = Rerun());
            listMenu.Items.Add("Abbrechen", Icons.Cancel(), (s, e) => _ = CancelJob());
            listMenu.Items.Add("Im Web-Browser öffnen", Icons.Browser(), (s, e) => OpenInBrowser());
            listMenu.Items.Add(new ToolStripSeparator());
            listMenu.Items.Add("Löschen", Icons.Delete(), (s, e) => _ = DeleteJob());
            list.MouseDown += (s, e) =>
            {
                if (e.Button != MouseButtons.Right) return;
                int i = list.IndexFromPoint(e.Location);
                if (i >= 0) list.SelectedIndex = i;
            };
            list.ContextMenuStrip = listMenu;

            // --- Auftragsansicht
            BuildWelcome();
            BuildJobView();
            var center = new FramePanel { Dock = DockStyle.Fill };
            center.Controls.Add(jobView);
            center.Controls.Add(welcome);

            // --- Aufgabenbereich rechts
            var task = new FramePanel { Dock = DockStyle.Fill };
            task.Controls.Add(BuildTaskPane());

            split1.Panel1.Controls.Add(nav);
            split1.Panel2.Controls.Add(split2);
            split2.Panel1.Controls.Add(center);
            split2.Panel2.Controls.Add(task);
            foreach (var sc in new[] { split1, split2 })
            {
                sc.BackColor = Office.Back;
                sc.SplitterWidth = Office.S(5);
                sc.Panel1.BackColor = sc.Panel2.BackColor = Office.Back;
            }
            var root = new Panel { Dock = DockStyle.Fill, Padding = new Padding(Office.S(4)), BackColor = Office.Back };
            root.Controls.Add(split1);
            Controls.Add(root);
            Controls.Add(tools);
            Controls.Add(menu);
            Controls.Add(statusBar);

            Load += (s, e) =>
            {
                split1.Panel1MinSize = Office.S(200);
                split2.Panel2MinSize = Office.S(200);
                split1.SplitterDistance = Math.Max(Office.S(200), Math.Min(cfg.NavWidth, Width / 2));
                split2.SplitterDistance = Math.Max(Office.S(300), split2.Width - Math.Max(Office.S(200), cfg.TaskPaneWidth) - split2.SplitterWidth);
                split2.Panel2Collapsed = !cfg.TaskPaneVisible;
                taskPaneItem.Checked = cfg.TaskPaneVisible;
            };
        }

        void BuildWelcome()
        {
            var head = new PaneHeader("Magic Box") { Note = "Datei rein – Doku raus" };
            var box = new FlowLayoutPanel { Location = new Point(Office.S(24), Office.S(48)), FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, BackColor = Color.White };
            var title = new Label { Text = "Willkommen bei der Magic Box", Font = Office.TitleFont, ForeColor = Office.Title, AutoSize = true, Margin = new Padding(0, 0, 0, Office.S(10)) };
            welcomeText.AutoSize = true;
            welcomeText.UseMnemonic = false;
            welcomeText.MaximumSize = new Size(Office.S(560), 0);
            welcomeText.Text =
                "Die Magic Box nimmt Dateien statisch auseinander – sie werden nie ausgeführt – und lässt das lokale " +
                "Sprachmodell daraus eine verständliche Dokumentation schreiben.\n\n" +
                "1.  Erkennen & entpacken: Dateityp, Passwort-Archive, UPX, kodierte Skript-Stufen\n" +
                "2.  Zerlegen: Header, Imports, Strings, Pseudocode, .NET-Dekompilierung, Makros\n" +
                "3.  Bewerten: YARA, capa/MITRE ATT&CK, Fähigkeiten, IOCs\n" +
                "4.  Dokumentieren: Bericht und Antworten auf deine Fragen zur Datei\n\n" +
                "Dateien einfach ins Fenster ziehen oder über „Datei analysieren …“ auswählen.";
            welcomeLink.Margin = new Padding(0, Office.S(16), 0, 0);
            welcomeLink.Font = Office.UiBold;
            welcomeLink.LinkClicked += (s, e) => WelcomeAction();
            box.Controls.AddRange(new Control[] { title, welcomeText, welcomeLink });
            welcome.Controls.Add(box);
            welcome.Controls.Add(head);
            SetWelcome("", "Datei analysieren …");
        }

        Action welcomeAction;
        void WelcomeAction() => (welcomeAction ?? ChooseFiles)();

        void SetWelcome(string message, string link, Action action = null)
        {
            welcomeAction = action;
            welcomeLink.Text = link;
            welcomeLink.Visible = link.Length > 0;
            if (message.Length > 0)
            {
                welcomeText.ForeColor = Office.Bad;
                welcomeText.Text = message;
            }
        }

        void BuildJobView()
        {
            var info = new GradientPanel { Dock = DockStyle.Top, TopColor = Color.White, BottomColor = Office.SubTop, BottomLine = true, Padding = new Padding(Office.S(10), Office.S(6), Office.S(10), Office.S(8)) };
            var grid = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, AutoSize = true, BackColor = Color.Transparent };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            var left = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, BackColor = Color.Transparent, Dock = DockStyle.Fill, Margin = new Padding(0) };
            chips.Margin = new Padding(0, Office.S(4), 0, 0);
            left.Controls.Add(meta);
            left.Controls.Add(sha);
            left.Controls.Add(chips);
            sha.LinkClicked += (s, e) => CopySha();
            steps.MinimumSize = new Size(Office.S(280), Office.S(42));
            grid.Controls.Add(left, 0, 0);
            grid.Controls.Add(steps, 1, 0);

            progressRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            progressRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            progressRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            progressRow.Dock = DockStyle.Top;
            progress.Dock = DockStyle.Fill;
            progress.Margin = new Padding(0, Office.S(3), Office.S(6), Office.S(3));
            pct.Margin = new Padding(0, Office.S(2), Office.S(6), 0);
            stage.Margin = new Padding(0, Office.S(2), 0, 0);
            progressRow.Controls.Add(progress, 0, 0);
            progressRow.Controls.Add(pct, 1, 0);
            progressRow.Controls.Add(stage, 2, 0);
            grid.Controls.Add(progressRow, 0, 1);
            grid.SetColumnSpan(progressRow, 2);

            var ask = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, Height = Office.S(46), BackColor = Color.Transparent, Margin = new Padding(0, Office.S(4), 0, 0) };
            ask.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            ask.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Office.S(96)));
            askBox.Dock = DockStyle.Fill;
            askButton.Dock = DockStyle.Fill;
            askButton.Image = Icons.Ask();
            askButton.TextImageRelation = TextImageRelation.ImageBeforeText;
            askButton.Click += (s, e) => _ = AskQuestion();
            askBox.KeyDown += (s, e) =>
            {
                if (e.KeyCode == Keys.Enter && e.Control) { e.SuppressKeyPress = true; _ = AskQuestion(); }
            };
            ask.Controls.Add(askBox, 0, 0);
            ask.Controls.Add(askButton, 1, 0);
            grid.Controls.Add(ask, 0, 2);
            grid.SetColumnSpan(ask, 2);
            info.Controls.Add(grid);
            // Höhe des Kopfbereichs folgt dem Inhalt (Etiketten können umbrechen, Fortschritt ein-/ausgeblendet)
            grid.SizeChanged += (s, e) => info.Height = grid.Height + info.Padding.Vertical;
            left.SizeChanged += (s, e) => chips.MaximumSize = new Size(Math.Max(Office.S(100), left.Width), 0);

            // Register: Bericht · KI live · Protokoll
            var reportPage = new TabPage("Bericht") { BackColor = Color.White };
            if (Type.GetType("Mono.Runtime") == null)
            {
                browser = new WebBrowser
                {
                    Dock = DockStyle.Fill, AllowWebBrowserDrop = false, ScriptErrorsSuppressed = true,
                    WebBrowserShortcutsEnabled = true, IsWebBrowserContextMenuEnabled = true,
                };
                browser.Navigating += (s, e) =>
                {
                    // Bericht stammt aus der Analyse fremder Dateien: keine Navigation, Links nicht öffnen
                    if (!e.Url.ToString().StartsWith("about:", StringComparison.OrdinalIgnoreCase)) e.Cancel = true;
                };
                browser.NewWindow += (s, e) => e.Cancel = true;
                reportPage.Controls.Add(browser);
            }
            else
            {
                reportPage.Controls.Add(reportFallback); // Mono (Tests unter Linux): Markdown statt HTML
            }
            reportPage.Controls.Add(reportPlaceholder);
            reportPlaceholder.BringToFront();
            var aiPage = new TabPage("KI live") { BackColor = Color.White, Padding = new Padding(Office.S(4)) };
            aiWait.Height = Office.S(34);
            aiWait.Padding = new Padding(Office.S(8), 0, 0, 0);
            aiPage.Controls.Add(aiBox);
            aiPage.Controls.Add(aiWait);
            var logPage = new TabPage("Protokoll") { BackColor = Color.White, Padding = new Padding(Office.S(4)) };
            logPage.Controls.Add(logBox);
            tabs.TabPages.AddRange(new[] { reportPage, aiPage, logPage });
            tabs.Padding = new Point(Office.S(12), Office.S(4));

            var tabHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(Office.S(6), Office.S(6), Office.S(6), Office.S(6)), BackColor = Color.White };
            tabHost.Controls.Add(tabs);
            jobView.Controls.Add(tabHost);
            jobView.Controls.Add(info);
            jobView.Controls.Add(jobHeader);
        }

        Control BuildTaskPane()
        {
            var host = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
            var header = new PaneHeader("Neue Analyse");
            var close = new Label
            {
                Text = "×", Font = new Font("Tahoma", 11f, FontStyle.Bold), ForeColor = Color.White, BackColor = Color.Transparent,
                Dock = DockStyle.Right, Width = Office.S(24), TextAlign = ContentAlignment.MiddleCenter, Cursor = Cursors.Hand,
            };
            close.Click += (s, e) => ToggleTaskPane();
            header.Controls.Add(close);
            var body = new GradientPanel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(Office.S(10)) };
            var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top, BackColor = Color.Transparent };

            Label Section(string text) => new Label
            {
                Text = text, Font = Office.UiBold, ForeColor = Office.Title, AutoSize = true, BackColor = Color.Transparent,
                Margin = new Padding(0, Office.S(10), 0, Office.S(2)),
            };
            Control Rule() => new Label { Height = 1, BackColor = Office.Border, Margin = new Padding(0, 0, 0, Office.S(6)) };
            TaskLink Link(string text, Image image, Action action)
            {
                var l = new TaskLink(text, image);
                l.Click += (s, e) => action();
                return l;
            }
            Label Caption(string text) => new Label { Text = text, AutoSize = true, BackColor = Color.Transparent, Margin = new Padding(0, Office.S(6), 0, Office.S(2)) };

            profileBox.Items.AddRange(new object[] { "🛡 Malware-Analyse", "📘 Software-Doku (ohne Malware-Prüfung)" });
            profileBox.SelectedIndex = cfg.Profile == "allgemein" ? 1 : 0;
            profileBox.SelectedIndexChanged += (s, e) => cfg.Profile = profileBox.SelectedIndex == 1 ? "allgemein" : "malware";
            questionBox.Height = Office.S(78);

            var controls = new List<Control>
            {
                Section("Datei analysieren"), Rule(),
                Link("Datei auswählen …", Icons.Open(), ChooseFiles),
                new Label { Text = "oder Dateien einfach ins Fenster ziehen.\nEXE, DLL, ELF, APK, JAR, ZIP/7z, Office, PDF, Skripte", AutoSize = true, ForeColor = Office.Muted, BackColor = Color.Transparent, Margin = new Padding(Office.S(28), 0, 0, Office.S(4)) },
                Caption("Profil:"), profileBox,
                Caption("Archiv-Passwort:"), passwordBox,
                Caption("Frage an die KI (optional):"), questionBox,
                new Label { Text = "z. B. „Suche die Funktion, die die Verbindung zum Server aufbaut, und erkläre sie verständlich.“", AutoSize = true, ForeColor = Office.Muted, BackColor = Color.Transparent },
                Section("Server"), Rule(),
                serverInfo,
                Link("Server-Einstellungen …", Icons.Settings(), OpenServerSettings),
                Link("Analyse-Werkzeuge …", Icons.Tools(), ShowTools),
                Link("KI-Verbindung testen", Icons.Refresh(), () => _ = CheckLlm()),
                Link("Verbindung ändern …", Icons.Browser(), ChangeServer),
            };
            flow.Controls.AddRange(controls.ToArray());
            void Fit()
            {
                int w = Math.Max(Office.S(150), body.ClientSize.Width - body.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth);
                foreach (Control c in flow.Controls)
                {
                    if (c is ComboBox || c is TextBox || (c is Label l && !l.AutoSize) || c.Height == 1) c.Width = w;
                    if (c is Label l2 && l2.AutoSize) l2.MaximumSize = new Size(w, 0);
                }
            }
            body.Resize += (s, e) => Fit();
            body.Controls.Add(flow);
            host.Controls.Add(body);
            host.Controls.Add(header);
            Fit();
            return host;
        }

        void WireDrop(Control c)
        {
            if (c is WebBrowser) return;
            c.AllowDrop = true;
            c.DragEnter += (s, e) =>
                e.Effect = e.Data.GetDataPresent(DataFormats.FileDrop) && connected ? DragDropEffects.Copy : DragDropEffects.None;
            c.DragDrop += (s, e) =>
            {
                if (e.Data.GetData(DataFormats.FileDrop) is string[] paths) UploadFiles(paths);
            };
            foreach (Control child in c.Controls) WireDrop(child);
            c.ControlAdded += (s, e) => WireDrop(e.Control);
        }

        // ================================================================== Verbindung & Anmeldung
        async Task Connect()
        {
            events?.Dispose();
            events = null;
            connected = false;
            UpdateCommands();
            if (string.IsNullOrWhiteSpace(cfg.ServerUrl) && !AskServer())
            {
                Disconnected("Noch kein Server eingestellt.", "Verbindung einrichten …", ChangeServer);
                return;
            }
            api?.Dispose();
            api = new ApiClient(cfg.ServerUrl) { Token = cfg.Token };
            SetStatus($"Verbinde mit {api.BaseUrl} …");
            connText.Text = "Verbinde …";
            try
            {
                var info = await api.AuthInfo();
                try
                {
                    status = await api.Get("/api/status");
                }
                catch (ApiException ex) when (ex.NeedsLogin)
                {
                    if (!await Login(info.Str("login")))
                    {
                        Disconnected("Nicht angemeldet.", "Anmelden …", () => _ = Connect());
                        return;
                    }
                    status = await api.Get("/api/status");
                }
            }
            catch (ApiException ex)
            {
                var hint = ex.Status == 403 ? ""
                    : ex.Status == 404 ? "\n\nDer Server kennt die Desktop-Anmeldung noch nicht – bitte die Magic Box auf dem Server " +
                                         "aktualisieren (git pull, rsync, systemctl restart magicbox-server)."
                    : "\n\nIst die Server-Adresse richtig? Läuft der Dienst magicbox-server?";
                Disconnected(ex.Message + hint, "Erneut verbinden", () => _ = Connect());
                return;
            }
            connected = true;
            ApplyStatus();
            await LoadJobs();
            events = new EventStream(api, ev => BeginInvokeSafe(() => OnEvent(ev)), up => BeginInvokeSafe(() => OnConnection(up)));
            SetStatus("Bereit");
            UpdateCommands();
        }

        async Task<bool> Login(string kind)
        {
            if (kind == "token")
            {
                using (var dlg = new TokenDialog(api.BaseUrl))
                {
                    if (dlg.ShowDialog(this) != DialogResult.OK) return false;
                    api.Token = dlg.Key;
                }
                try
                {
                    var st = await api.Get("/api/status");
                    cfg.Token = api.Token;
                    cfg.UserName = st.Obj("user").Str("name");
                    cfg.Save();
                    return true;
                }
                catch (ApiException ex)
                {
                    MessageBox.Show(this, ex.Message, "Anmelden", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }
            api.Token = "";
            using (var dlg = new BrowserLoginDialog(api))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Result == null) return false;
                api.Token = dlg.Result.Str("token");
                cfg.Token = api.Token;
                cfg.UserName = dlg.Result.Str("name");
                cfg.Save();
                Activate();
                return true;
            }
        }

        async Task Logout()
        {
            if (api != null)
            {
                try { await api.Post("/api/logout"); } catch (ApiException) { }
            }
            events?.Dispose();
            events = null;
            cfg.Token = "";
            cfg.Save();
            jobs.Clear();
            current = null;
            RenderList();
            RenderJob(true, false);
            connected = false;
            Disconnected("Abgemeldet.", "Anmelden …", () => _ = Connect());
        }

        void Disconnected(string message, string link, Action action)
        {
            connected = false;
            connText.Text = "Nicht verbunden";
            connText.ForeColor = Office.Bad;
            llmText.Text = "";
            SetStatus(message.Split('\n')[0]);
            current = null;
            jobView.Visible = false;
            welcome.Visible = true;
            SetWelcome(message, link, action);
            serverInfo.Text = $"{cfg.ServerUrl}\nnicht verbunden";
            UpdateCommands();
        }

        bool AskServer()
        {
            using (var dlg = new ConnectDialog(cfg.ServerUrl))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Url.Length == 0) return false;
                if (dlg.Url != cfg.ServerUrl) cfg.Token = "";
                cfg.ServerUrl = dlg.Url;
                cfg.Save();
                return true;
            }
        }

        void ChangeServer()
        {
            if (AskServer()) _ = Connect();
        }

        void ApplyStatus()
        {
            var llm = status.Obj("llm");
            var user = status.Obj("user");
            bool on = llm.Bool("enabled");
            llmText.Text = on ? $"KI: {llm.Str("model")}" : "KI aus";
            llmText.ToolTipText = on ? $"{llm.Str("provider")} @ {llm.Str("url")} – klicken zum Testen" : "KI ist in den Server-Einstellungen deaktiviert";
            llmText.ForeColor = Color.Black;
            var host = new Uri(api.BaseUrl).Host;
            var who = user.Str("method") == "none" ? "" : $" als {user.Str("name")}";
            connText.Text = $"Verbunden mit {host}{who}";
            connText.ForeColor = Color.Black;
            serverInfo.Text = $"{api.BaseUrl}\n{(who.Length > 0 ? "angemeldet" + who : "ohne Anmeldung")} · v{status.Str("version")}";
            Text = $"Magic Box – {host}";
            if (profileBox.Items.Count > 0 && cfg.Profile.Length == 0)
                profileBox.SelectedIndex = status.Str("profile") == "allgemein" ? 1 : 0;
            welcomeText.ForeColor = Color.Black;
            SetWelcome("", "Datei analysieren …");
        }

        void OnConnection(bool up)
        {
            if (!connected) return;
            if (up)
            {
                connText.ForeColor = Color.Black;
                if (statusText.Text.StartsWith("Verbindung unterbrochen")) SetStatus("Wieder verbunden");
                _ = Reload(); // Ereignisse während der Unterbrechung nachholen
            }
            else
            {
                connText.ForeColor = Office.Warn;
                SetStatus("Verbindung unterbrochen – verbinde neu …");
            }
        }

        async Task Reload()
        {
            if (api == null || !connected) return;
            try
            {
                status = await api.Get("/api/status");
                ApplyStatus();
                await LoadJobs();
            }
            catch (ApiException ex)
            {
                HandleError(ex);
            }
        }

        async Task LoadJobs()
        {
            var list2 = await api.Jobs();
            jobs.Clear();
            foreach (var d in list2) jobs[d.Str("id")] = new Job(d);
            RenderList();
            if (current != null && jobs.ContainsKey(current)) await SelectJob(current, false);
            else if (current == null && jobs.Count > 0) await SelectJob(jobs.Values.OrderByDescending(j => j.Created).First().Id, true);
            else RenderJob(true, false);
        }

        void HandleError(Exception ex)
        {
            if (ex is ApiException api401 && api401.NeedsLogin && !relogging)
            {
                relogging = true;
                cfg.Token = "";
                BeginInvokeSafe(async () =>
                {
                    MessageBox.Show(this, api401.Message, "Anmeldung", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    await Connect();
                    relogging = false;
                });
                return;
            }
            SetStatus(ex.Message);
            MessageBox.Show(this, ex.Message, "Magic Box", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        void BeginInvokeSafe(Action a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(a); } catch (InvalidOperationException) { }
        }

        void SetStatus(string text) => statusText.Text = text;

        // ================================================================== Aufträge
        void Upsert(Dictionary<string, object> d)
        {
            var id = d.Str("id");
            if (jobs.TryGetValue(id, out var old))
            {
                if (d.Int("rev") < old.Rev) return; // veralteter Stand – verwerfen
                foreach (var kv in d) old.D[kv.Key] = kv.Value;
            }
            else
            {
                jobs[id] = new Job(d);
            }
            RenderList();
            if (id == current) RenderJob(false, false);
        }

        void RenderList()
        {
            var ordered = jobs.Values.OrderByDescending(j => j.Created).ToList();
            list.BeginUpdate();
            list.Items.Clear();
            foreach (var j in ordered) list.Items.Add(j);
            int idx = ordered.FindIndex(j => j.Id == current);
            list.SelectedIndex = idx;
            list.EndUpdate();
            navHeader.Note = ordered.Count > 0 ? ordered.Count.ToString() : "";
        }

        async Task SelectJob(string id, bool switchTabs)
        {
            current = id;
            loading = true; // Live-Ereignisse bis zur Antwort ignorieren – Lücken werden danach erkannt
            RenderList();
            try
            {
                var detail = await api.Get($"/api/jobs/{id}");
                if (current != id) return;
                ai.Clear();
                ai.Append(detail.Str("ai"));
                aiLen = CpLen(ai.ToString());
                var log = detail.Strings("log");
                logTotal = detail.Get("log_total") is double lt ? (int)lt : log.Count;
                logBox.Text = string.Join("\r\n", log);
                Upsert(detail);
            }
            catch (ApiException ex)
            {
                if (ex.NeedsLogin) HandleError(ex);
                else SetStatus(ex.Message);
            }
            finally
            {
                if (current == id) loading = false;
            }
            RenderJob(true, switchTabs);
        }

        void RenderJob(bool fresh, bool switchTabs)
        {
            Job j = current != null && jobs.TryGetValue(current, out var x) ? x : null;
            welcome.Visible = j == null;
            jobView.Visible = j != null;
            UpdateCommands();
            if (j == null) return;

            bool running = j.Active;
            jobHeader.Text = j.Name;
            steps.Show(j);
            jobHeader.Note = steps.LevelText(j);
            var by = j.D.Str("created_by");
            meta.Text = $"{(j.D.Str("description").Length > 0 ? j.D.Str("description") : "…")} · {Job.Size(j.D.Num("size"))}" +
                        $"{(by.Length > 0 ? " · von " + by : "")} · {Job.Time(j.Created)}";
            var hash = j.D.Str("sha256");
            sha.Text = "SHA-256: " + (hash.Length > 24 ? hash.Substring(0, 24) + "…" : hash);
            cueTips.SetToolTip(sha, hash + "\nKlicken zum Kopieren");

            chips.SuspendLayout();
            chips.Controls.Clear();
            void Chip(string text, string kind) => chips.Controls.Add(new Chip(text, kind));
            Chip(j.D.Str("profile") == "allgemein" ? "Software-Doku" : "Malware-Profil", "neutral");
            if (j.Status == "done")
            {
                if (j.Risk.Length > 0) Chip($"Risiko {j.Risk}", j.Risk == "hoch" ? "bad" : j.Risk == "mittel" ? "warn" : "good");
                var verdict = j.D.Str("llm_verdict");
                if (verdict.Length > 0)
                    Chip($"KI: {verdict}", verdict.Contains("bösartig") || verdict.Contains("gefährlich") ? "bad"
                        : verdict.Contains("verdächtig") || verdict.Contains("auffällig") ? "warn" : "good");
                foreach (var d in j.D.Strings("detections")) Chip($"YARA: {d}", "bad");
                var c = j.D.Obj("counts");
                if (c.Int("high") + c.Int("medium") > 0) Chip($"{c.Int("high")} hoch · {c.Int("medium")} mittel · {c.Int("low")} niedrig", "neutral");
                if (j.D.Int("ioc_count") > 0) Chip($"{j.D.Int("ioc_count")} IOCs", "info");
                if (j.D.Str("llm_error").Length > 0) Chip("ohne KI-Text", "warn");
                int qa = j.D.Int("qa_count");
                if (qa > 0) Chip($"{qa} {(qa == 1 ? "Frage" : "Fragen")} beantwortet", "info");
                if (j.D.Str("notice").Length > 0) Chip(j.D.Str("notice"), "warn");
            }
            else if (j.FollowUp)
            {
                Chip(j.Status == "queued" ? "Frage wartet" : "KI beantwortet deine Frage", "info");
            }
            else
            {
                Chip(Job.StatusText(j.Status), j.Status == "error" ? "bad" : "neutral");
                if (j.D.Str("question").Length > 0) Chip("mit Frage an die KI", "info");
            }
            chips.ResumeLayout();

            progressRow.Visible = running;
            progress.Value = j.Progress;
            progress.Busy = j.Status == "running";
            pct.Text = $"{j.Progress} %";
            stage.Text = j.Status == "queued" ? (j.FollowUp ? "Frage wartet auf einen freien Platz" : "wartet auf einen freien Platz") : j.Stage;

            bool llmOn = status.Obj("llm").Bool("enabled");
            bool ready = j.Status == "done" && llmOn;
            askBox.Enabled = askButton.Enabled = ready;
            askButton.Text = j.FollowUp ? "…" : "&Fragen";
            askBox.BackColor = ready ? Color.White : Color.FromArgb(240, 243, 248);
            SetCue(askBox, !llmOn ? "Die KI ist in den Server-Einstellungen deaktiviert."
                : ready ? "Frage zur Datei, z. B. „Suche die Funktion, die die Daten verschlüsselt, und erkläre sie.“ (Strg+Eingabe)"
                : j.FollowUp ? "Die KI beantwortet gerade eine Frage …"
                : running ? "Fragen kannst du stellen, sobald die Analyse fertig ist."
                : "Fragen gehen nur zu fertigen Analysen – ggf. „Erneut analysieren“.");

            // Bericht
            if (j.HasReport)
            {
                var key = $"{j.Id}:{j.Finished}";
                if (key != reportKey)
                {
                    reportKey = key;
                    _ = LoadReport(j.Id, key);
                }
            }
            else
            {
                reportKey = "";
                reportPlaceholder.Visible = true;
                reportPlaceholder.ForeColor = j.Status == "error" ? Office.Bad : Office.Muted;
                reportPlaceholder.Text = j.Status == "error" ? "Fehler: " + j.D.Str("error")
                    : j.Status == "cancelled" ? "Abgebrochen"
                    : running ? "Analyse läuft … im Register „KI live“ kannst du zusehen." : "";
            }

            if (fresh)
            {
                aiBox.Text = ai.Length > 0 ? Crlf(ai.ToString()) : running ? "" : "(keine KI-Ausgabe)";
                ScrollToEnd(aiBox);
                ScrollToEnd(logBox);
                if (switchTabs && j.Status == "running") tabs.SelectedIndex = 1;
                else if (switchTabs && j.Status == "done") tabs.SelectedIndex = 0;
            }
            UpdateAiWait();
        }

        async Task LoadReport(string id, string key)
        {
            try
            {
                if (browser != null)
                {
                    var html = await api.Text($"/api/jobs/{id}/report.classic");
                    if (reportKey != key) return;
                    browser.DocumentText = html;
                }
                else
                {
                    var md = await api.Text($"/api/jobs/{id}/report.md");
                    if (reportKey != key) return;
                    reportFallback.Text = Crlf(md);
                }
                reportPlaceholder.Visible = false;
            }
            catch (ApiException ex)
            {
                if (reportKey != key) return;
                reportKey = "";
                reportPlaceholder.Visible = true;
                reportPlaceholder.Text = "Bericht nicht ladbar: " + ex.Message;
            }
            UpdateCommands();
        }

        void UpdateCommands()
        {
            Job j = current != null && jobs.TryGetValue(current, out var x) ? x : null;
            foreach (var i in needsServer) i.Enabled = connected;
            foreach (var i in needsJob) i.Enabled = connected && j != null;
            foreach (var i in needsReport) i.Enabled = connected && j != null && j.HasReport;
            foreach (var i in needsActive) i.Enabled = connected && j != null && j.Active;
            foreach (var i in needsIdle) i.Enabled = connected && j != null && !j.Active;
        }

        // ================================================================== Live-Ereignisse
        void OnEvent(Dictionary<string, object> ev)
        {
            switch (ev.Str("type"))
            {
                case "unauthorized":
                    if (connected) HandleError(new ApiException(401, "Die Anmeldung ist abgelaufen – bitte neu anmelden."));
                    break;
                case "job":
                {
                    var d = ev.Obj("job");
                    var id = d.Str("id");
                    jobs.TryGetValue(id, out var before);
                    string beforeStatus = before?.Status, beforeStage = before?.Stage ?? "", beforeAsk = before?.Ask ?? "";
                    if (id == current && d.Str("stage").StartsWith("KI") && !beforeStage.StartsWith("KI")) llmSince = DateTime.Now;
                    Upsert(d);
                    var now = d.Str("status");
                    if (before != null && beforeStatus != now && id == current)
                    {
                        if (now == "running")
                        {
                            _ = SelectJob(id, false); // neu laden – eine Nachfrage setzt KI-Text und Protokoll fort
                            tabs.SelectedIndex = 1;
                        }
                        if (now == "done") tabs.SelectedIndex = 0;
                    }
                    if (beforeStatus == "running" && now == "done")
                        Notify(beforeAsk.Length > 0 ? $"Antwort zu {d.Str("name")} steht im Bericht." : $"{d.Str("name")} ist fertig.");
                    if (beforeStatus == "running" && now == "error") Notify($"{d.Str("name")}: {d.Str("error")}", true);
                    break;
                }
                case "token":
                {
                    if (ev.Str("id") != current || loading) break;
                    var text = ev.Str("text");
                    int pos = ev.Get("pos") is double p ? (int)p : aiLen;
                    if (pos > aiLen) { _ = SelectJob(current, false); break; } // Lücke → Stand neu laden
                    var fresh = CpSkip(text, aiLen - pos);
                    aiLen = Math.Max(aiLen, pos + CpLen(text));
                    if (fresh.Length > 0)
                    {
                        if (aiBox.Text.StartsWith("(keine KI-Ausgabe)")) aiBox.Clear();
                        ai.Append(fresh);
                        aiBox.AppendText(Crlf(fresh));
                    }
                    if (text.Trim().Length > 0 && !text.Contains("────")) lastTokenAt = DateTime.Now;
                    else llmSince = DateTime.Now;
                    UpdateAiWait();
                    break;
                }
                case "log":
                {
                    if (ev.Str("id") != current || loading) break;
                    int n = ev.Get("n") is double nn ? (int)nn : logTotal;
                    if (n > logTotal) { _ = SelectJob(current, false); break; }
                    if (n < logTotal) break;
                    logTotal = n + 1;
                    logBox.AppendText((logBox.TextLength > 0 ? "\r\n" : "") + ev.Str("line"));
                    break;
                }
                case "deleted":
                {
                    var id = ev.Str("id");
                    jobs.Remove(id);
                    if (current == id) current = null;
                    RenderList();
                    RenderJob(true, false);
                    break;
                }
            }
        }

        void Notify(string text, bool error = false)
        {
            SetStatus(text);
            if (!ContainsFocus) FlashTaskbar();
            if (error) System.Media.SystemSounds.Exclamation.Play();
        }

        void UpdateAiWait()
        {
            Job j = current != null && jobs.TryGetValue(current, out var x) ? x : null;
            bool llmPhase = j != null && j.Status == "running" && j.Stage.StartsWith("KI");
            double idle = (DateTime.Now - lastTokenAt).TotalSeconds;
            if (!llmPhase || idle < 4)
            {
                aiWait.Visible = false;
                return;
            }
            var since = (int)Math.Min(idle, (DateTime.Now - (llmSince == DateTime.MinValue ? DateTime.Now : llmSince)).TotalSeconds);
            // Hat das Modell in diesem Auftrag schon geschrieben, ist es geladen – dann ist es das Einlesen der Eingabe
            bool loaded = ai.ToString().Split('\n').Any(l => l.Trim().Length > 0 && !l.Contains("────"));
            aiWait.Text = since < 20
                ? "⏳  Das Sprachmodell liest die Eingabe ein …"
                : loaded
                    ? $"⏳  Das Sprachmodell liest den nächsten Abschnitt ein (seit {since} s) – auf der CPU dauert das Einlesen " +
                      "langer Eingaben mehrere Minuten, die Antwort kommt danach zügig."
                    : $"⏳  Warte auf das Sprachmodell (seit {since} s) – beim ersten Aufruf lädt Ollama das Modell in den Speicher; " +
                      "dazu kommt das Einlesen der Eingabe, auf der CPU zusammen oft mehrere Minuten.";
            aiWait.Visible = true;
        }

        void Animate()
        {
            bool any = jobs.Values.Any(j => j.Status == "running");
            if (!any) return;
            list.Spin = (list.Spin + 24) % 360;
            list.Invalidate();
            steps.Tick();
            progress.Tick();
        }

        // ================================================================== Aktionen
        void ChooseFiles()
        {
            if (!connected) return;
            using (var dlg = new OpenFileDialog { Multiselect = true, Title = "Datei analysieren", Filter = "Alle Dateien|*.*" })
                if (dlg.ShowDialog(this) == DialogResult.OK) UploadFiles(dlg.FileNames);
        }

        void UploadFiles(string[] paths)
        {
            if (!connected) return;
            var files = paths.Where(File.Exists).ToArray();
            if (paths.Any(Directory.Exists))
                MessageBox.Show(this, "Ordner bitte als ZIP-Archiv hochladen.", "Magic Box", MessageBoxButtons.OK, MessageBoxIcon.Information);
            if (files.Length == 0) return;
            var question = questionBox.Text.Trim();
            questionBox.Clear(); // die Frage gilt für genau diese Datei(en)
            foreach (var f in files) _ = Upload(f, question);
        }

        async Task Upload(string file, string question)
        {
            uploadsRunning++;
            var name = Path.GetFileName(file);
            uploadText.Visible = uploadBar.Visible = true;
            uploadText.Text = $"Lade hoch: {name}";
            uploadBar.Value = 0;
            var prog = new Progress<double>(v =>
            {
                uploadBar.Value = (int)(v * 100);
                uploadText.Text = $"Lade hoch: {name} ({v:P0})";
            });
            try
            {
                var profile = profileBox.SelectedIndex == 1 ? "allgemein" : "malware";
                var job = await api.Upload(file, profile, passwordBox.Text.Trim(), question, prog, CancellationToken.None);
                Upsert(job);
                await SelectJob(job.Str("id"), true);
                SetStatus($"{name} wird analysiert …");
            }
            catch (Exception ex) when (ex is ApiException || ex is IOException || ex is UnauthorizedAccessException)
            {
                if (ex is ApiException ae && ae.NeedsLogin) HandleError(ae);
                else MessageBox.Show(this, $"{name}: {ex.Message}", "Hochladen", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                if (--uploadsRunning == 0) uploadText.Visible = uploadBar.Visible = false;
            }
        }

        async Task AskQuestion()
        {
            var q = askBox.Text.Trim();
            if (q.Length == 0 || current == null || !askBox.Enabled) return;
            try
            {
                Upsert(await api.Post($"/api/jobs/{current}/ask", new Dictionary<string, object> { ["question"] = q }));
                askBox.Clear();
                tabs.SelectedIndex = 1;
            }
            catch (ApiException ex)
            {
                HandleError(ex);
            }
        }

        async Task Rerun()
        {
            if (current == null) return;
            try
            {
                ai.Clear();
                aiLen = 0;
                Upsert(await api.Post($"/api/jobs/{current}/rerun"));
                RenderJob(true, true);
            }
            catch (ApiException ex) { HandleError(ex); }
        }

        async Task CancelJob()
        {
            if (current == null) return;
            try { Upsert(await api.Post($"/api/jobs/{current}/cancel")); }
            catch (ApiException ex) { HandleError(ex); }
        }

        async Task DeleteJob()
        {
            if (current == null || !jobs.TryGetValue(current, out var j) || j.Active) return;
            if (MessageBox.Show(this, $"„{j.Name}“ inklusive Probe und Bericht löschen?", "Löschen", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try { await api.Obj(HttpMethod.Delete, $"/api/jobs/{j.Id}"); }
            catch (ApiException ex) { HandleError(ex); }
        }

        async void SaveAs(string action, string fileName, string filter)
        {
            if (current == null || !jobs.TryGetValue(current, out var j)) return;
            using (var dlg = new SaveFileDialog { FileName = $"{Path.GetFileNameWithoutExtension(j.Name)}_{fileName}", Filter = filter, Title = "Speichern unter" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    File.WriteAllBytes(dlg.FileName, await api.Bytes($"/api/jobs/{j.Id}/{action}"));
                    SetStatus($"Gespeichert: {dlg.FileName}");
                }
                catch (Exception ex) when (ex is ApiException || ex is IOException || ex is UnauthorizedAccessException)
                {
                    MessageBox.Show(this, ex.Message, "Speichern", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        void OpenInBrowser()
        {
            if (api == null) return;
            var url = api.BaseUrl + "/" + (current != null ? "#" + current : "");
            if (!Program.OpenUrl(url)) MessageBox.Show(this, "Browser ließ sich nicht öffnen:\n" + url, "Magic Box");
        }

        void CopySha()
        {
            if (current != null && jobs.TryGetValue(current, out var j))
            {
                Clipboard.SetText(j.D.Str("sha256"));
                SetStatus("SHA-256 in die Zwischenablage kopiert.");
            }
        }

        void CopySelection()
        {
            if (ActiveControl is TextBox t && t.SelectionLength > 0) t.Copy();
            else if (tabs.SelectedIndex == 1 && aiBox.SelectionLength > 0) aiBox.Copy();
            else if (tabs.SelectedIndex == 2 && logBox.SelectionLength > 0) logBox.Copy();
        }

        void ToggleTaskPane()
        {
            split2.Panel2Collapsed = !split2.Panel2Collapsed;
            cfg.TaskPaneVisible = !split2.Panel2Collapsed;
            taskPaneItem.Checked = cfg.TaskPaneVisible;
        }

        void OpenServerSettings()
        {
            if (!connected) return;
            using (var dlg = new ServerSettingsForm(api))
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    SetStatus("Server-Einstellungen gespeichert – gelten ab dem nächsten Auftrag.");
                    _ = Reload();
                }
        }

        void ShowTools()
        {
            if (!connected) return;
            using (var dlg = new ToolsForm(status.List("tools"))) dlg.ShowDialog(this);
        }

        async Task CheckLlm()
        {
            if (!connected) return;
            SetStatus("Prüfe KI-Verbindung …");
            try
            {
                var r = await api.Post("/api/llm/check");
                llmText.ForeColor = r.Bool("ok") ? Office.Good : Office.Bad;
                SetStatus(r.Str("message"));
                MessageBox.Show(this, r.Str("message"), "KI-Verbindung", MessageBoxButtons.OK,
                    r.Bool("ok") ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (ApiException ex) { HandleError(ex); }
        }

        void About()
        {
            MessageBox.Show(this,
                $"Magic Box {Program.Version}\n\nDatei rein – verständliche Doku raus.\n" +
                "Statische Analyse mit lokalem Sprachmodell; diese App spricht über die REST-API mit dem Server.\n\n" +
                $"Server: {cfg.ServerUrl}\nServer-Version: {status.Str("version", "–")}",
                "Info über Magic Box", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ================================================================== Hilfen
        static string Crlf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");

        static void ScrollToEnd(TextBox t)
        {
            t.SelectionStart = t.TextLength;
            t.ScrollToCaret();
        }

        /// <summary>Länge in Unicode-Zeichen (Codepoints) – so zählt der Server die Positionen im KI-Text.</summary>
        public static int CpLen(string s)
        {
            int n = 0;
            for (int i = 0; i < s.Length; i++, n++)
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
            return n;
        }

        public static string CpSkip(string s, int codepoints)
        {
            int i = 0;
            while (codepoints > 0 && i < s.Length)
            {
                i += char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
                codepoints--;
            }
            return s.Substring(i);
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern bool FlashWindow(IntPtr hwnd, bool invert);

        void FlashTaskbar()
        {
            try { FlashWindow(Handle, true); } catch (Exception) { }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

        static void SetCue(TextBox box, string text)
        {
            // Platzhaltertext (EM_SETCUEBANNER); bei mehrzeiligen Feldern zeigt Windows ihn nicht – dann als Tooltip
            try { SendMessage(box.Handle, 0x1501, (IntPtr)1, text); } catch (Exception) { }
            box.AccessibleDescription = text;
            cueTips.SetToolTip(box, text);
        }

        static readonly ToolTip cueTips = new ToolTip();

        void ApplySavedBounds()
        {
            var parts = cfg.WindowBounds.Split(',');
            if (parts.Length == 4 && parts.All(p => int.TryParse(p, out _)))
            {
                var r = new Rectangle(int.Parse(parts[0]), int.Parse(parts[1]), int.Parse(parts[2]), int.Parse(parts[3]));
                if (Screen.AllScreens.Any(sc => sc.WorkingArea.IntersectsWith(r)))
                {
                    StartPosition = FormStartPosition.Manual;
                    Bounds = r;
                }
            }
            if (cfg.Maximized) WindowState = FormWindowState.Maximized;
        }

        void SaveLayout()
        {
            var b = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
            cfg.WindowBounds = $"{b.X},{b.Y},{b.Width},{b.Height}";
            cfg.Maximized = WindowState == FormWindowState.Maximized;
            cfg.NavWidth = split1.SplitterDistance;
            if (!split2.Panel2Collapsed) cfg.TaskPaneWidth = split2.Width - split2.SplitterDistance - split2.SplitterWidth;
            cfg.Save();
            events?.Dispose();
        }
    }
}
