using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.Windows.Forms;

namespace MagicBox.Desktop
{
    /// <summary>Ein Auftrag, wie ihn die API liefert (/api/jobs, Ereignis "job").</summary>
    public sealed class Job
    {
        public Dictionary<string, object> D;
        public Job(Dictionary<string, object> d) { D = d; }
        public string Id => D.Str("id");
        public string Name => D.Str("name");
        public string Status => D.Str("status");
        public string Stage => D.Str("stage");
        public string Risk => D.Str("risk");
        public string Ask => D.Str("ask");
        public int Progress => D.Int("progress");
        public int Rev => D.Int("rev");
        public double Created => D.Num("created");
        public double Finished => D.Num("finished");
        public bool Active => Status == "queued" || Status == "running";
        public bool FollowUp => Ask.Length > 0 && Active;
        public bool HasReport => Status == "done" || (FollowUp && Finished > 0);

        public static string StatusText(string s) => s switch
        {
            "queued" => "wartet", "running" => "läuft", "done" => "fertig", "error" => "Fehler", "cancelled" => "abgebrochen", _ => s,
        };

        public string SubLine
        {
            get
            {
                string sub = Status switch
                {
                    "done" => D.Str("description"),
                    "queued" => FollowUp ? "Frage wartet" : "in Warteschlange",
                    "error" => D.Str("error", "Fehler"),
                    _ => $"{StatusText(Status)} · {Stage}",
                };
                return $"{sub} · {Time(Created)}";
            }
        }

        public static string Time(double unix) => unix <= 0 ? "" :
            DateTimeOffset.FromUnixTimeMilliseconds((long)(unix * 1000)).LocalDateTime.ToString("dd.MM.yy HH:mm", CultureInfo.GetCultureInfo("de-DE"));

        public static string Size(double n)
        {
            string[] u = { "B", "KB", "MB", "GB" };
            int i = 0;
            while (n >= 1024 && i < u.Length - 1) { n /= 1024; i++; }
            return i == 0 ? $"{n:0} {u[i]}" : $"{n:0.0} {u[i]}";
        }
    }

    /// <summary>Kopf eines Bereichs wie in Outlook 2003 („Posteingang“): dunkelblauer Verlauf, weiße Schrift.</summary>
    public sealed class PaneHeader : Control
    {
        string note = "";
        public string Note { get => note; set { note = value ?? ""; Invalidate(); } }

        public PaneHeader(string text)
        {
            Text = text;
            Dock = DockStyle.Top;
            Height = Office.S(28);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint, true);
        }

        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            Office.Gradient(g, ClientRectangle, Office.HeaderTop, Office.HeaderBottom);
            var r = new Rectangle(Office.S(8), 0, Width - Office.S(16), Height);
            TextRenderer.DrawText(g, note, Office.UiFont, r, Color.FromArgb(205, 222, 250),
                TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
            var noteWidth = string.IsNullOrEmpty(note) ? 0 : TextRenderer.MeasureText(note, Office.UiFont).Width + Office.S(12);
            r.Width -= noteWidth;
            TextRenderer.DrawText(g, Text, Office.HeaderFont, r, Color.White,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis |
                TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>Heller Unterkopf (z. B. „Datei analysieren“ im Aufgabenbereich).</summary>
    public sealed class SubHeader : Control
    {
        public SubHeader(string text)
        {
            Text = text;
            Dock = DockStyle.Top;
            Height = Office.S(22);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            Office.Gradient(g, ClientRectangle, Office.SubTop, Office.SubBottom);
            using (var pen = new Pen(Office.Border)) g.DrawLine(pen, 0, Height - 1, Width, Height - 1);
            TextRenderer.DrawText(g, Text, Office.UiBold, new Rectangle(Office.S(6), 0, Width - Office.S(12), Height),
                Office.Title, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }
    }

    /// <summary>Fläche mit senkrechtem Verlauf (Aufgabenbereich, Kopf der Detailansicht).</summary>
    public class GradientPanel : Panel
    {
        public Color TopColor = Office.TaskTop, BottomColor = Office.TaskBottom;
        public bool BottomLine;

        public GradientPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            Office.Gradient(e.Graphics, ClientRectangle, TopColor, BottomColor);
            if (BottomLine)
                using (var pen = new Pen(Office.Border)) e.Graphics.DrawLine(pen, 0, Height - 1, Width, Height - 1);
        }
    }

    /// <summary>Rahmen in der Office-Randfarbe um einen Bereich.</summary>
    public sealed class FramePanel : Panel
    {
        public FramePanel()
        {
            Padding = new Padding(1);
            BackColor = Office.Border;
        }
    }

    /// <summary>Schritt-Anzeige Analyse → KI → Bericht.</summary>
    public sealed class StepIndicator : Control
    {
        static readonly string[] Labels = { "Analyse", "KI", "Bericht" };
        int current = -1;
        bool failed, busy, skipKi, followUp;
        float spin;

        public StepIndicator()
        {
            Height = Office.S(40);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }

        public int Current => current;

        public void Show(Job j)
        {
            int p = j.Progress;
            bool ki = j.Stage.StartsWith("KI");
            if (j.Status == "done") current = 3;
            else if (j.Ask.Length > 0) current = p >= 95 ? 2 : 1;
            else if (j.Status == "queued") current = 0;
            else if (j.Status == "error" || j.Status == "cancelled") current = p >= 95 ? 2 : p >= 45 ? 1 : 0;
            else current = ki ? 1 : p >= 95 ? 2 : 0;
            failed = j.Status == "error" || j.Status == "cancelled";
            busy = j.Status == "running";
            skipKi = j.Status == "done" && j.D.Str("model").Length == 0;
            followUp = j.Ask.Length > 0;
            Invalidate();
        }

        public void Tick() { if (busy) { spin = (spin + 30) % 360; Invalidate(); } }

        public string LevelText(Job j) =>
            j.Status == "done" ? "abgeschlossen" : j.Status == "error" ? "Fehler" : j.Status == "cancelled" ? "abgebrochen"
            : $"{(followUp ? "Nachfrage · " : "")}Schritt {Math.Min(current + 1, 3)} von 3";

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            int d = Office.S(16), w = Width / 3;
            int cy = Office.S(4) + d / 2;
            for (int i = 1; i < 3; i++)
            {
                bool done = i <= current && !(failed && i == current);
                using (var pen = new Pen(done ? Office.DarkBorder : Color.FromArgb(170, 185, 210), Office.S(2)))
                    g.DrawLine(pen, w * (i - 1) + w / 2 + d / 2, cy, w * i + w / 2 - d / 2, cy);
            }
            for (int i = 0; i < 3; i++)
            {
                var r = new Rectangle(w * i + w / 2 - d / 2, cy - d / 2, d, d);
                bool skipped = i == 1 && skipKi;
                string label = i == 1 && followUp ? "KI · Frage" : Labels[i];
                Color text = Office.Muted;
                if (skipped)
                {
                    using (var pen = new Pen(Color.Silver, Office.S(2))) g.DrawEllipse(pen, r);
                    label += " (aus)";
                }
                else if (i < current)
                {
                    using (var b = new LinearGradientBrush(r, Color.FromArgb(120, 160, 225), Office.DarkBorder, LinearGradientMode.Vertical))
                        g.FillEllipse(b, r);
                    using (var f = new Font("Tahoma", d * 0.6f, FontStyle.Bold, GraphicsUnit.Pixel))
                    using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                        g.DrawString("✓", f, Brushes.White, r, sf);
                    text = Color.Black;
                }
                else if (i == current && failed)
                {
                    using (var b = new SolidBrush(Color.FromArgb(255, 220, 220))) g.FillEllipse(b, r);
                    using (var pen = new Pen(Office.Bad, Office.S(2))) g.DrawEllipse(pen, r);
                    text = Office.Bad;
                }
                else if (i == current)
                {
                    using (var b = new LinearGradientBrush(r, Office.SelTop, Office.SelBottom, LinearGradientMode.Vertical))
                        g.FillEllipse(b, r);
                    using (var pen = new Pen(Office.SelBorder, Office.S(1))) g.DrawEllipse(pen, r);
                    if (busy)
                        using (var arc = new Pen(Office.SelBorder, Office.S(2)))
                            g.DrawArc(arc, Rectangle.Inflate(r, -Office.S(3), -Office.S(3)), spin, 120);
                    text = Office.Title;
                }
                else
                {
                    g.FillEllipse(Brushes.White, r);
                    using (var pen = new Pen(Color.FromArgb(170, 185, 210), Office.S(2))) g.DrawEllipse(pen, r);
                }
                var lr = new Rectangle(w * i, r.Bottom + Office.S(3), w, Office.S(16));
                TextRenderer.DrawText(g, label, i == current && !failed ? Office.UiBold : Office.UiFont, lr, text,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.SingleLine);
            }
        }
    }

    /// <summary>Fortschrittsbalken im Office-Stil (blauer Verlauf, Lichtreflex solange gearbeitet wird).</summary>
    public sealed class OfficeProgress : Control
    {
        int value;
        float shimmer = -0.4f;
        public bool Busy;
        public int Value { get => value; set { this.value = Math.Max(0, Math.Min(100, value)); Invalidate(); } }

        public OfficeProgress()
        {
            Height = Office.S(14);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint, true);
        }

        public void Tick()
        {
            if (!Busy) return;
            shimmer += 0.04f;
            if (shimmer > 1.4f) shimmer = -0.4f;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            g.FillRectangle(Brushes.White, r);
            int w = (int)(r.Width * Math.Max(3, value) / 100.0);
            var fill = new Rectangle(1, 1, Math.Max(1, w - 1), r.Height - 1);
            Office.Gradient(g, fill, Color.FromArgb(140, 185, 245), Color.FromArgb(25, 85, 185));
            if (Busy && fill.Width > 4)
            {
                int sw = Math.Max(Office.S(30), fill.Width / 4);
                int x = (int)(shimmer * fill.Width);
                var sr = new Rectangle(x, 1, sw, fill.Height);
                using (var b = new LinearGradientBrush(new Rectangle(x - 1, 0, sw + 2, Height),
                           Color.FromArgb(0, Color.White), Color.FromArgb(0, Color.White), LinearGradientMode.Horizontal))
                {
                    var blend = new ColorBlend
                    {
                        Positions = new[] { 0f, 0.5f, 1f },
                        Colors = new[] { Color.FromArgb(0, Color.White), Color.FromArgb(110, Color.White), Color.FromArgb(0, Color.White) },
                    };
                    b.InterpolationColors = blend;
                    g.SetClip(fill);
                    g.FillRectangle(b, sr);
                    g.ResetClip();
                }
            }
            using (var pen = new Pen(Office.Border)) g.DrawRectangle(pen, r);
        }
    }

    /// <summary>Kleines farbiges Etikett (Risiko, KI-Urteil, YARA …).</summary>
    public sealed class Chip : Control
    {
        readonly Color back, fore;

        public Chip(string text, string kind)
        {
            Text = text;
            (back, fore) = kind switch
            {
                "bad" => (Color.FromArgb(255, 224, 224), Office.Bad),
                "warn" => (Color.FromArgb(255, 240, 200), Color.FromArgb(160, 80, 0)),
                "good" => (Color.FromArgb(222, 245, 222), Office.Good),
                "info" => (Color.FromArgb(221, 234, 252), Office.Title),
                _ => (Color.FromArgb(240, 243, 248), Color.FromArgb(70, 80, 100)),
            };
            var size = TextRenderer.MeasureText(text, Office.UiBold, Size.Empty, TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            Size = new Size(size.Width + Office.S(12), size.Height + Office.S(5));
            Margin = new Padding(0, 0, Office.S(5), Office.S(3));
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint |
                     ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Office.Rounded(new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f), Office.S(4)))
            using (var b = new SolidBrush(back))
            using (var pen = new Pen(ControlPaint.Light(fore, 1.2f)))
            {
                g.FillPath(b, path);
                g.DrawPath(pen, path);
            }
            TextRenderer.DrawText(g, Text, Office.UiBold, ClientRectangle, fore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>Auftragsliste: zweizeilige Einträge wie in Outlook 2003, Auswahl orange, Hover gelb.</summary>
    public sealed class JobList : ListBox
    {
        int hover = -1;
        public float Spin;

        public JobList()
        {
            DrawMode = DrawMode.OwnerDrawFixed;
            ItemHeight = Office.S(42);
            BorderStyle = BorderStyle.None;
            IntegralHeight = false;
            Font = Office.UiFont;
            SetStyle(ControlStyles.OptimizedDoubleBuffer, true);
        }

        public Job JobAt(int i) => i >= 0 && i < Items.Count ? Items[i] as Job : null;

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int i = IndexFromPoint(e.Location);
            if (i != hover) { hover = i; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            hover = -1;
            Invalidate();
        }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= Items.Count) return;
            var j = (Job)Items[e.Index];
            var g = e.Graphics;
            var r = e.Bounds;
            bool selected = (e.State & DrawItemState.Selected) != 0;
            g.FillRectangle(Brushes.White, r);
            var box = Rectangle.Inflate(r, -Office.S(3), -Office.S(2));
            if (selected || e.Index == hover)
            {
                Office.Gradient(g, box, selected ? Office.SelTop : Office.HotTop, selected ? Office.SelBottom : Office.HotBottom);
                using (var pen = new Pen(Office.SelBorder)) g.DrawRectangle(pen, box);
            }
            else
            {
                using (var pen = new Pen(Color.FromArgb(225, 232, 243))) g.DrawLine(pen, r.Left + Office.S(8), r.Bottom - 1, r.Right - Office.S(8), r.Bottom - 1);
            }
            int ic = Office.S(18);
            var icon = new Rectangle(box.Left + Office.S(6), box.Top + (box.Height - ic) / 2, ic, ic);
            Icons.Status(g, icon, j.Status, j.Risk, Spin);
            int x = icon.Right + Office.S(8);
            var nameRect = new Rectangle(x, box.Top + Office.S(4), box.Right - x - Office.S(4), Office.S(15));
            TextRenderer.DrawText(g, j.Name, Office.UiBold, nameRect, Color.Black,
                TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            var subRect = new Rectangle(x, nameRect.Bottom + Office.S(1), nameRect.Width, Office.S(14));
            TextRenderer.DrawText(g, j.SubLine, Office.UiFont, subRect, j.Status == "error" ? Office.Bad : Office.Muted,
                TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            if (j.Status == "running")
            {
                var bar = new Rectangle(x, box.Bottom - Office.S(5), nameRect.Width - Office.S(4), Office.S(3));
                g.FillRectangle(Brushes.White, bar);
                var fill = new Rectangle(bar.X, bar.Y, bar.Width * Math.Max(3, j.Progress) / 100, bar.Height);
                Office.Gradient(g, fill, Color.FromArgb(140, 185, 245), Color.FromArgb(25, 85, 185));
                using (var pen = new Pen(Office.Border)) g.DrawRectangle(pen, bar);
            }
        }
    }

    /// <summary>Große Schaltfläche unten im Navigationsbereich (wie „E-Mail“, „Kalender“ in Outlook 2003).</summary>
    public sealed class NavButton : Control
    {
        readonly Image image;
        bool hot;
        public bool Selected;

        public NavButton(string text, Image image)
        {
            Text = text;
            this.image = image;
            Dock = DockStyle.Bottom;
            Height = Office.S(30);
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                     ControlStyles.UserPaint, true);
        }

        protected override void OnMouseEnter(EventArgs e) { hot = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hot = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var top = Selected ? Office.SelTop : hot ? Office.HotTop : Office.LightTop;
            var bottom = Selected ? Office.SelBottom : hot ? Office.HotBottom : Office.LightBottom;
            Office.Gradient(g, ClientRectangle, top, bottom);
            using (var pen = new Pen(Office.DarkBorder)) g.DrawLine(pen, 0, 0, Width, 0);
            int x = Office.S(8);
            if (image != null)
            {
                g.DrawImage(image, x, (Height - image.Height) / 2, image.Width, image.Height);
                x += image.Width + Office.S(8);
            }
            TextRenderer.DrawText(g, Text, Office.UiBold, new Rectangle(x, 0, Width - x, Height), Color.Black,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }
    }

    /// <summary>Verknüpfung im Aufgabenbereich (Symbol + blauer Text, beim Darüberfahren unterstrichen).</summary>
    public sealed class TaskLink : Control
    {
        readonly Image image;
        bool hot;

        public TaskLink(string text, Image image)
        {
            Text = text;
            this.image = image;
            Cursor = Cursors.Hand;
            TabStop = true;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint |
                     ControlStyles.SupportsTransparentBackColor | ControlStyles.Selectable, true);
            BackColor = Color.Transparent;
            var size = TextRenderer.MeasureText(text, Office.UiFont);
            Size = new Size(Office.S(26) + size.Width, Math.Max(Office.S(20), size.Height + Office.S(4)));
            Margin = new Padding(Office.S(4), Office.S(1), 0, Office.S(1));
        }

        protected override void OnMouseEnter(EventArgs e) { hot = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hot = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter || e.KeyCode == Keys.Space) OnClick(EventArgs.Empty);
            base.OnKeyDown(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            if (image != null) g.DrawImage(image, Office.S(2), (Height - image.Height) / 2, image.Width, image.Height);
            using (var f = new Font(Office.UiFont, hot ? FontStyle.Underline : FontStyle.Regular))
                TextRenderer.DrawText(g, Text, f, new Rectangle(Office.S(24), 0, Width - Office.S(24), Height),
                    hot ? Color.FromArgb(0, 102, 255) : Office.Link, TextFormatFlags.Left | TextFormatFlags.VerticalCenter |
                    TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
            if (Focused) ControlPaint.DrawFocusRectangle(g, new Rectangle(Office.S(22), 1, Width - Office.S(23), Height - 2));
        }
    }
}
