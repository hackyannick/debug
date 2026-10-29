using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace MagicBox.Desktop
{
    /// <summary>Office-2003-Farben („Luna Blau“), Schriften und Größen.</summary>
    public static class Office
    {
        public static readonly Color Back = Color.FromArgb(195, 218, 249);          // Hintergrund zwischen den Bereichen
        public static readonly Color Border = Color.FromArgb(101, 147, 207);        // Rahmen der Bereiche
        public static readonly Color DarkBorder = Color.FromArgb(59, 97, 156);
        public static readonly Color HeaderTop = Color.FromArgb(89, 135, 214);      // Outlook-Bereichskopf (dunkel)
        public static readonly Color HeaderBottom = Color.FromArgb(3, 56, 147);
        public static readonly Color LightTop = Color.FromArgb(227, 239, 255);      // Symbolleisten/Unterköpfe (hell)
        public static readonly Color LightMid = Color.FromArgb(203, 225, 252);
        public static readonly Color LightBottom = Color.FromArgb(123, 164, 224);
        public static readonly Color SubTop = Color.FromArgb(227, 239, 255);
        public static readonly Color SubBottom = Color.FromArgb(196, 218, 250);
        public static readonly Color Title = Color.FromArgb(21, 66, 139);           // dunkelblaue Überschriften
        public static readonly Color Link = Color.FromArgb(0, 51, 204);
        public static readonly Color HotTop = Color.FromArgb(255, 255, 222);        // Hover (gelb)
        public static readonly Color HotBottom = Color.FromArgb(255, 203, 136);
        public static readonly Color SelTop = Color.FromArgb(255, 213, 140);        // ausgewählt (orange)
        public static readonly Color SelBottom = Color.FromArgb(255, 173, 85);
        public static readonly Color SelBorder = Color.FromArgb(0, 0, 128);
        public static readonly Color TaskTop = Color.FromArgb(221, 236, 254);       // Aufgabenbereich
        public static readonly Color TaskBottom = Color.FromArgb(166, 199, 243);
        public static readonly Color Muted = Color.FromArgb(90, 100, 120);
        public static readonly Color Good = Color.FromArgb(0, 128, 0);
        public static readonly Color Warn = Color.FromArgb(204, 102, 0);
        public static readonly Color Bad = Color.FromArgb(192, 0, 0);

        public static Font UiFont = new Font("Tahoma", 8.25f);
        public static Font UiBold = new Font("Tahoma", 8.25f, FontStyle.Bold);
        public static Font HeaderFont = new Font("Tahoma", 12f, FontStyle.Bold);
        public static Font TitleFont = new Font("Tahoma", 11f, FontStyle.Bold);
        public static Font SmallFont = new Font("Tahoma", 7.5f);
        public static Font Mono = new Font(FontExists("Consolas") ? "Consolas" : "Courier New", 9f);

        static float scale = 1f;
        public static int S(int px) => (int)Math.Round(px * scale);

        public static void Init()
        {
            using (var g = Graphics.FromHwnd(IntPtr.Zero)) scale = Math.Max(1f, g.DpiX / 96f);
            ToolStripManager.Renderer = new ToolStripProfessionalRenderer(new Colors()) { RoundedEdges = true };
        }

        static bool FontExists(string name)
        {
            using (var f = new Font(name, 9f)) return string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase);
        }

        public static void Gradient(Graphics g, Rectangle r, Color top, Color bottom, bool vertical = true)
        {
            if (r.Width <= 0 || r.Height <= 0) return;
            using (var b = new LinearGradientBrush(r, top, bottom, vertical ? LinearGradientMode.Vertical : LinearGradientMode.Horizontal))
                g.FillRectangle(b, r);
        }

        public static GraphicsPath Rounded(RectangleF r, float radius)
        {
            var p = new GraphicsPath();
            float d = radius * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        /// <summary>Farbtabelle für Menüs, Symbolleisten und Statusleiste wie in Office 2003.</summary>
        sealed class Colors : ProfessionalColorTable
        {
            public Colors() { UseSystemColors = false; }
            public override Color ToolStripGradientBegin => LightTop;
            public override Color ToolStripGradientMiddle => LightMid;
            public override Color ToolStripGradientEnd => LightBottom;
            public override Color ToolStripBorder => DarkBorder;
            public override Color ToolStripPanelGradientBegin => Color.FromArgb(158, 190, 245);
            public override Color ToolStripPanelGradientEnd => Color.FromArgb(196, 218, 250);
            public override Color ToolStripContentPanelGradientBegin => Back;
            public override Color ToolStripContentPanelGradientEnd => Back;
            public override Color MenuStripGradientBegin => Color.FromArgb(158, 190, 245);
            public override Color MenuStripGradientEnd => Color.FromArgb(196, 218, 250);
            public override Color StatusStripGradientBegin => Color.FromArgb(158, 190, 245);
            public override Color StatusStripGradientEnd => Color.FromArgb(196, 218, 250);
            public override Color MenuBorder => SelBorder;
            public override Color MenuItemBorder => SelBorder;
            public override Color MenuItemSelected => Color.FromArgb(255, 238, 194);
            public override Color MenuItemSelectedGradientBegin => HotTop;
            public override Color MenuItemSelectedGradientEnd => HotBottom;
            public override Color MenuItemPressedGradientBegin => LightTop;
            public override Color MenuItemPressedGradientMiddle => LightMid;
            public override Color MenuItemPressedGradientEnd => Color.FromArgb(152, 186, 238);
            public override Color ToolStripDropDownBackground => Color.FromArgb(246, 246, 246);
            public override Color ImageMarginGradientBegin => LightTop;
            public override Color ImageMarginGradientMiddle => LightMid;
            public override Color ImageMarginGradientEnd => Color.FromArgb(135, 173, 228);
            public override Color ButtonSelectedBorder => SelBorder;
            public override Color ButtonSelectedHighlight => Color.FromArgb(255, 238, 194);
            public override Color ButtonSelectedGradientBegin => HotTop;
            public override Color ButtonSelectedGradientMiddle => Color.FromArgb(255, 225, 172);
            public override Color ButtonSelectedGradientEnd => HotBottom;
            public override Color ButtonPressedBorder => SelBorder;
            public override Color ButtonPressedGradientBegin => Color.FromArgb(254, 128, 62);
            public override Color ButtonPressedGradientMiddle => Color.FromArgb(255, 177, 109);
            public override Color ButtonPressedGradientEnd => Color.FromArgb(255, 223, 154);
            public override Color ButtonCheckedGradientBegin => SelTop;
            public override Color ButtonCheckedGradientMiddle => Color.FromArgb(255, 195, 116);
            public override Color ButtonCheckedGradientEnd => SelBottom;
            public override Color CheckBackground => SelTop;
            public override Color CheckSelectedBackground => Color.FromArgb(254, 128, 62);
            public override Color GripDark => Color.FromArgb(39, 65, 118);
            public override Color GripLight => Color.White;
            public override Color SeparatorDark => Color.FromArgb(106, 140, 203);
            public override Color SeparatorLight => Color.FromArgb(241, 249, 255);
            public override Color OverflowButtonGradientBegin => Color.FromArgb(127, 177, 250);
            public override Color OverflowButtonGradientMiddle => Color.FromArgb(82, 127, 208);
            public override Color OverflowButtonGradientEnd => Color.FromArgb(0, 53, 145);
        }
    }

    /// <summary>Symbole (16×16, skaliert) – selbst gezeichnet, damit die App ohne Bild-Ressourcen auskommt.</summary>
    public static class Icons
    {
        static Bitmap Make(Action<Graphics> draw)
        {
            int size = Office.S(16);
            var bmp = new Bitmap(size, size);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.ScaleTransform(size / 16f, size / 16f);
                draw(g);
            }
            return bmp;
        }

        static readonly Pen Outline = new Pen(Color.FromArgb(70, 70, 70), 1f);

        public static Bitmap Open() => Make(g =>
        {
            using (var back = new SolidBrush(Color.FromArgb(232, 180, 60)))
            using (var front = new SolidBrush(Color.FromArgb(255, 214, 102)))
            using (var pen = new Pen(Color.FromArgb(160, 110, 20)))
            {
                g.FillRectangle(back, 1, 3, 6, 3);
                g.FillRectangle(back, 1, 5, 13, 9);
                g.DrawRectangle(pen, 1, 5, 13, 9);
                var front2 = new[] { new PointF(3, 8), new PointF(15.5f, 8), new PointF(13.5f, 14), new PointF(1, 14) };
                g.FillPolygon(front, front2);
                g.DrawPolygon(pen, front2);
            }
        });

        public static Bitmap Report() => Make(g =>
        {
            g.FillRectangle(Brushes.White, 3, 1, 10, 14);
            g.DrawRectangle(Outline, 3, 1, 10, 14);
            using (var blue = new SolidBrush(Color.FromArgb(49, 106, 197)))
            {
                g.FillRectangle(blue, 4, 2, 9, 3);
                for (int y = 7; y <= 13; y += 2) g.FillRectangle(Brushes.Gray, 5, y, y == 13 ? 4 : 7, 1);
            }
        });

        public static Bitmap Save() => Make(g =>
        {
            using (var body = new SolidBrush(Color.FromArgb(49, 89, 173)))
            {
                g.FillRectangle(body, 1, 1, 14, 14);
                g.FillRectangle(Brushes.White, 4, 2, 8, 5);
                g.FillRectangle(Brushes.LightGray, 4, 10, 8, 5);
                g.FillRectangle(body, 9, 11, 2, 3);
            }
        });

        public static Bitmap Print() => Make(g =>
        {
            g.FillRectangle(Brushes.White, 4, 1, 8, 5);
            g.DrawRectangle(Outline, 4, 1, 8, 5);
            using (var body = new SolidBrush(Color.FromArgb(150, 150, 160))) g.FillRectangle(body, 1, 6, 14, 6);
            g.DrawRectangle(Outline, 1, 6, 14, 6);
            g.FillRectangle(Brushes.White, 4, 10, 8, 5);
            g.DrawRectangle(Outline, 4, 10, 8, 5);
            g.FillRectangle(Brushes.LimeGreen, 12, 7, 2, 1);
        });

        public static Bitmap Rerun() => Make(g =>
        {
            using (var pen = new Pen(Color.FromArgb(0, 140, 0), 2.2f))
                g.DrawArc(pen, 2.5f, 2.5f, 11, 11, 300, 280);
            using (var b = new SolidBrush(Color.FromArgb(0, 140, 0)))
                g.FillPolygon(b, new[] { new PointF(9, 0.5f), new PointF(15, 3.5f), new PointF(9.5f, 7) });
        });

        public static Bitmap Cancel() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(214, 40, 40))) g.FillEllipse(b, 1, 1, 14, 14);
            using (var pen = new Pen(Color.FromArgb(140, 0, 0))) g.DrawEllipse(pen, 1, 1, 14, 14);
            g.FillRectangle(Brushes.White, 4, 7, 8, 2.5f);
        });

        public static Bitmap Delete() => Make(g =>
        {
            using (var pen = new Pen(Color.FromArgb(200, 30, 30), 2.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawLine(pen, 3, 3, 13, 13);
                g.DrawLine(pen, 13, 3, 3, 13);
            }
        });

        public static Bitmap Ask() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(49, 106, 197)))
            {
                g.FillEllipse(b, 1, 1, 14, 11);
                g.FillPolygon(b, new[] { new PointF(4, 10), new PointF(3, 15), new PointF(8, 11) });
            }
            using (var f = new Font("Tahoma", 8f, FontStyle.Bold, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString("?", f, Brushes.White, new RectangleF(1, 1, 14, 11), sf);
        });

        public static Bitmap Settings() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(110, 120, 140)))
            {
                for (int i = 0; i < 8; i++)
                {
                    var st = g.Save();
                    g.TranslateTransform(8, 8);
                    g.RotateTransform(i * 45);
                    g.FillRectangle(b, -1.5f, -7.5f, 3, 4);
                    g.Restore(st);
                }
                g.FillEllipse(b, 2.5f, 2.5f, 11, 11);
            }
            g.FillEllipse(Brushes.White, 5.5f, 5.5f, 5, 5);
        });

        public static Bitmap Tools() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(200, 50, 40)))
            using (var dark = new SolidBrush(Color.FromArgb(130, 20, 20)))
            {
                g.FillRectangle(b, 1, 6, 14, 9);
                g.FillRectangle(dark, 1, 6, 14, 2);
                g.DrawRectangle(Outline, 1, 6, 14, 9);
                g.DrawRectangle(Outline, 5, 3, 6, 3);
                g.FillRectangle(Brushes.Silver, 7, 9, 2, 3);
            }
        });

        public static Bitmap Refresh() => Make(g =>
        {
            using (var pen = new Pen(Color.FromArgb(49, 106, 197), 2f))
            {
                g.DrawArc(pen, 2, 2, 12, 12, 200, 140);
                g.DrawArc(pen, 2, 2, 12, 12, 20, 140);
            }
            using (var b = new SolidBrush(Color.FromArgb(49, 106, 197)))
            {
                g.FillPolygon(b, new[] { new PointF(12, 0.5f), new PointF(15.5f, 5), new PointF(10, 5) });
                g.FillPolygon(b, new[] { new PointF(4, 15.5f), new PointF(0.5f, 11), new PointF(6, 11) });
            }
        });

        public static Bitmap Browser() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(70, 140, 220))) g.FillEllipse(b, 1, 1, 14, 14);
            using (var pen = new Pen(Color.White, 1f))
            {
                g.DrawEllipse(pen, 5, 1.5f, 6, 13);
                g.DrawLine(pen, 1.5f, 8, 14.5f, 8);
                g.DrawLine(pen, 3, 4.5f, 13, 4.5f);
                g.DrawLine(pen, 3, 11.5f, 13, 11.5f);
            }
            using (var pen = new Pen(Color.FromArgb(30, 80, 160))) g.DrawEllipse(pen, 1, 1, 14, 14);
        });

        public static Bitmap Key() => Make(g =>
        {
            using (var b = new SolidBrush(Color.FromArgb(220, 170, 30)))
            using (var pen = new Pen(Color.FromArgb(150, 100, 0)))
            {
                g.FillEllipse(b, 1, 4, 7, 7);
                g.DrawEllipse(pen, 1, 4, 7, 7);
                g.FillRectangle(b, 7, 6.5f, 8, 2);
                g.FillRectangle(b, 12, 8, 2, 3);
                g.FillRectangle(b, 9.5f, 8, 1.5f, 2);
            }
            g.FillEllipse(Brushes.White, 3, 6.5f, 2.5f, 2.5f);
        });

        public static Bitmap TaskPane() => Make(g =>
        {
            g.FillRectangle(Brushes.White, 1, 2, 14, 12);
            using (var b = new SolidBrush(Color.FromArgb(166, 199, 243))) g.FillRectangle(b, 9, 3, 5, 10);
            using (var pen = new Pen(Color.FromArgb(49, 89, 173))) g.DrawRectangle(pen, 1, 2, 14, 12);
        });

        /// <summary>Status-Symbol eines Auftrags (Liste).</summary>
        public static void Status(Graphics g, Rectangle r, string status, string risk, float spin)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var c = Color.FromArgb(150, 150, 150);
            string glyph = "";
            switch (status)
            {
                case "done":
                    c = risk == "hoch" ? Office.Bad : risk == "mittel" ? Color.FromArgb(230, 130, 0)
                        : risk == "gering" ? Color.FromArgb(40, 150, 40) : Color.FromArgb(49, 106, 197); // Software-Doku: blau
                    glyph = "✓";
                    break;
                case "error": c = Office.Bad; glyph = "!"; break;
                case "cancelled": c = Color.FromArgb(130, 130, 130); glyph = "–"; break;
                case "queued": c = Color.FromArgb(120, 140, 170); glyph = "…"; break;
            }
            if (status == "running")
            {
                using (var track = new Pen(Color.FromArgb(200, 215, 240), 3f)) g.DrawEllipse(track, r);
                using (var arc = new Pen(Color.FromArgb(49, 106, 197), 3f)) g.DrawArc(arc, r, spin, 110);
                return;
            }
            using (var b = new LinearGradientBrush(r, ControlPaint.Light(c, 0.4f), c, LinearGradientMode.Vertical))
                g.FillEllipse(b, r);
            using (var pen = new Pen(ControlPaint.Dark(c, 0.1f))) g.DrawEllipse(pen, r);
            using (var f = new Font("Tahoma", r.Height * 0.55f, FontStyle.Bold, GraphicsUnit.Pixel))
            using (var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
                g.DrawString(glyph, f, Brushes.White, r, sf);
        }
    }
}
