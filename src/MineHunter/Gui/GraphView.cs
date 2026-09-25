using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using MineHunter.Model;

namespace MineHunter.Gui
{
    /// <summary>Draws the threat graph of one finding: autostart / tamper  →  file  →  running process  →  network.</summary>
    public static class GraphView
    {
        const double W = 268, H = 78, ColGap = 96, RowGap = 26, Pad = 24;

        sealed class Node { public Entity E; public int Col; public double X, Y; public double Order; }
        sealed class Edge { public Node From, To; public string Rel; public bool Directed = true; }

        static Brush B(string hex) { var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex); b.Freeze(); return b; }
        public static readonly Brush Bad = B("#FF4D5E"), Orange = B("#FF8A3D"), Warn = B("#F5B942"), Minor = B("#6E7FB0"), Good = B("#2ECC8F"), Text = B("#E8ECF7"), Muted = B("#8E99BA"), Panel = B("#1D2440"), Bg = B("#161B2E");

        public static Brush AccentFor(Entity e)
        {
            if (e.Trusted) return Good;
            if (e.Score >= 85) return Bad;
            if (e.Score >= 60) return Orange;
            if (e.Score >= 30) return Warn;
            return Minor;
        }

        static int ColOf(EntityKind k)
        {
            switch (k)
            {
                case EntityKind.File: return 1;
                case EntityKind.Process: return 2;
                case EntityKind.Network: return 3;
                default: return 0;
            }
        }

        public static void Render(Canvas c, Finding f)
        {
            c.Children.Clear();
            if (f == null) { c.Width = 300; c.Height = 100; return; }

            var nodes = f.Entities.Select(e => new Node { E = e, Col = ColOf(e.Kind), Order = -e.Score }).ToList();
            var byId = nodes.ToDictionary(n => n.E.Id, n => n, StringComparer.OrdinalIgnoreCase);
            var edges = new List<Edge>();

            // pseudo nodes for the connections a process has
            foreach (var n in nodes.Where(x => x.E.Kind == EntityKind.Process).ToList())
            {
                string conns = n.E.P("connections");
                if (string.IsNullOrEmpty(conns)) continue;
                var ne = new Entity { Id = "net:" + n.E.Id, Kind = EntityKind.Network, Title = conns.Length > 60 ? conns.Substring(0, 57) + "..." : conns, Location = conns, Score = 0 };
                var nn = new Node { E = ne, Col = 3, Order = 0 };
                nodes.Add(nn); byId[ne.Id] = nn;
                edges.Add(new Edge { From = n, To = nn, Rel = "connects to" });
            }

            foreach (var l in f.Links)
            {
                Node a, b; if (!byId.TryGetValue(l.From, out a) || !byId.TryGetValue(l.To, out b)) continue;
                string rel = l.Relation; var from = a; var to = b;
                if (rel == "runs image") { from = b; to = a; rel = "is running as"; }
                else if (rel == "started by") { from = b; to = a; rel = "started"; }
                bool directed = !(rel == "same content" || rel == "same folder" || rel == "same list");
                edges.Add(new Edge { From = from, To = to, Rel = rel, Directed = directed });
            }

            // compact used columns
            var used = nodes.Select(n => n.Col).Distinct().OrderBy(x => x).ToList();
            foreach (var n in nodes) n.Col = used.IndexOf(n.Col);

            // barycentre ordering: reduce edge crossings
            for (int pass = 0; pass < 2; pass++)
                foreach (var col in Enumerable.Range(0, used.Count))
                {
                    foreach (var n in nodes.Where(x => x.Col == col))
                    {
                        var nb = edges.Where(e => e.To == n && e.From.Col < col).Select(e => e.From.Order).Concat(edges.Where(e => e.From == n && e.To.Col < col).Select(e => e.To.Order)).ToList();
                        if (nb.Count > 0) n.Order = nb.Average();
                    }
                    int i = 0; foreach (var n in nodes.Where(x => x.Col == col).OrderBy(x => x.Order).ToList()) n.Order = i++;
                }

            int maxRows = Enumerable.Range(0, used.Count).Max(col => nodes.Count(n => n.Col == col));
            double totalH = maxRows * H + (maxRows - 1) * RowGap;
            foreach (var col in Enumerable.Range(0, used.Count))
            {
                var colNodes = nodes.Where(n => n.Col == col).OrderBy(n => n.Order).ToList();
                double h = colNodes.Count * H + (colNodes.Count - 1) * RowGap;
                double y0 = Pad + 28 + (totalH - h) / 2;
                for (int i = 0; i < colNodes.Count; i++) { colNodes[i].X = Pad + col * (W + ColGap); colNodes[i].Y = y0 + i * (H + RowGap); }
            }
            c.Width = Pad * 2 + used.Count * W + (used.Count - 1) * ColGap;
            c.Height = Pad * 2 + 28 + totalH + 44;

            // column captions
            string[] captions = { Loc.L("Autostart / tampering", "Автозапуск / вмешательство"), Loc.L("Files", "Файлы"), Loc.L("Running processes", "Запущенные процессы"), Loc.L("Network", "Сеть") };
            for (int i = 0; i < used.Count; i++)
            {
                var t = new TextBlock { Text = captions[used[i]].ToUpperInvariant(), Foreground = Muted, FontSize = 11, FontWeight = FontWeights.SemiBold };
                Canvas.SetLeft(t, Pad + i * (W + ColGap)); Canvas.SetTop(t, Pad - 4); c.Children.Add(t);
            }

            // edges first (below the boxes)
            int sideIdx = 0;
            foreach (var e in edges)
            {
                Point p1, p2; Brush brush = e.Directed ? (Brush)Muted : B("#55608A");
                var fig = new PathFigure(); var geo = new PathGeometry();
                if (e.From.Col != e.To.Col)
                {
                    bool fwd = e.From.Col < e.To.Col;
                    p1 = new Point(e.From.X + (fwd ? W : 0), e.From.Y + H / 2); p2 = new Point(e.To.X + (fwd ? 0 : W), e.To.Y + H / 2);
                    double dx = (fwd ? 1 : -1) * ColGap * 0.55;
                    fig.StartPoint = p1; fig.Segments.Add(new BezierSegment(new Point(p1.X + dx, p1.Y), new Point(p2.X - dx, p2.Y), p2, true));
                }
                else
                {
                    // same column: bracket on the right-hand side
                    sideIdx++;
                    p1 = new Point(e.From.X + W, e.From.Y + H / 2); p2 = new Point(e.To.X + W, e.To.Y + H / 2);
                    double bulge = 26 + 10 * (sideIdx % 3);
                    fig.StartPoint = p1; fig.Segments.Add(new BezierSegment(new Point(p1.X + bulge, p1.Y), new Point(p2.X + bulge, p2.Y), p2, true));
                }
                geo.Figures.Add(fig);
                var path = new Path { Data = geo, Stroke = brush, StrokeThickness = 1.6 };
                if (!e.Directed) path.StrokeDashArray = new DoubleCollection { 4, 3 };
                c.Children.Add(path);
                if (e.Directed && e.From.Col != e.To.Col)
                {
                    bool fwd = e.From.Col < e.To.Col; double dir = fwd ? 1 : -1;
                    var arrow = new Polygon { Fill = brush, Points = new PointCollection { p2, new Point(p2.X - dir * 9, p2.Y - 5), new Point(p2.X - dir * 9, p2.Y + 5) } };
                    c.Children.Add(arrow);
                }
                var lab = new TextBlock { Text = Loc.Relation(e.Rel), Foreground = Muted, FontSize = 10.5, Background = Bg, Padding = new Thickness(4, 1, 4, 1) };
                lab.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                double lx = (p1.X + p2.X) / 2 - lab.DesiredSize.Width / 2, ly = (p1.Y + p2.Y) / 2 - lab.DesiredSize.Height / 2;
                if (e.From.Col == e.To.Col) { lx = Math.Max(p1.X, p2.X) + 8; }
                Canvas.SetLeft(lab, lx); Canvas.SetTop(lab, ly); c.Children.Add(lab);
            }

            foreach (var n in nodes)
            {
                var acc = n.E.Kind == EntityKind.Network ? Minor : AccentFor(n.E);
                var box = new Border { Width = W, Height = H, CornerRadius = new CornerRadius(11), Background = Panel, BorderBrush = acc, BorderThickness = new Thickness(1.6), Padding = new Thickness(12, 8, 12, 8) };
                var sp = new StackPanel();
                var top = new Grid();
                top.ColumnDefinitions.Add(new ColumnDefinition()); top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                top.Children.Add(new TextBlock { Text = Loc.KindName(n.E.Kind).ToUpperInvariant(), Foreground = Muted, FontSize = 10.5, FontWeight = FontWeights.SemiBold });
                if (n.E.Kind != EntityKind.Network)
                {
                    var sc = new TextBlock { Text = n.E.Trusted ? "✓" : n.E.Score.ToString(), Foreground = acc, FontWeight = FontWeights.Bold, FontSize = 12 };
                    Grid.SetColumn(sc, 1); top.Children.Add(sc);
                }
                sp.Children.Add(top);
                sp.Children.Add(new TextBlock { Text = n.E.Title, Foreground = Text, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 3, 0, 0) });
                string loc = n.E.Kind == EntityKind.Task ? (n.E.P("taskPath") ?? n.E.Location) : n.E.Location;
                sp.Children.Add(new TextBlock { Text = loc ?? "", Foreground = Muted, FontSize = 11, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 2, 0, 0) });
                box.Child = sp;
                var ev = n.E.Evidence.Where(x => x.Weight > 0).OrderByDescending(x => x.Weight).Take(6).Select(x => (x.Weight >= 0 ? "+" : "") + x.Weight + "  " + Loc.Ev(x)).ToList();
                box.ToolTip = n.E.Title + "\n" + (loc ?? "") + (ev.Count > 0 ? "\n\n" + string.Join("\n", ev) : "");
                Canvas.SetLeft(box, n.X); Canvas.SetTop(box, n.Y); c.Children.Add(box);
            }

            // legend
            double ly2 = c.Height - 34; double lx2 = Pad;
            Action<Brush, string> leg = (br, txt) =>
            {
                var dot = new Ellipse { Width = 10, Height = 10, Fill = br }; Canvas.SetLeft(dot, lx2); Canvas.SetTop(dot, ly2 + 4); c.Children.Add(dot);
                var t = new TextBlock { Text = txt, Foreground = Muted, FontSize = 11 }; t.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                Canvas.SetLeft(t, lx2 + 16); Canvas.SetTop(t, ly2 + 1); c.Children.Add(t); lx2 += 16 + t.DesiredSize.Width + 22;
            };
            leg(Bad, Loc.L("score ≥ 85", "балл ≥ 85")); leg(Orange, Loc.L("≥ 60", "≥ 60")); leg(Warn, Loc.L("≥ 30", "≥ 30")); leg(Minor, Loc.L("minor", "мелкое")); leg(Good, Loc.L("trusted", "доверенное"));
        }
    }
}
