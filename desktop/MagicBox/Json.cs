using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace MagicBox.Desktop
{
    /// <summary>Kleiner JSON-Parser/-Serialisierer (ohne externe Abhängigkeiten).
    /// Objekte → Dictionary&lt;string, object&gt;, Arrays → List&lt;object&gt;, Zahlen → double.</summary>
    public static class Json
    {
        public static object Parse(string text)
        {
            var p = new Parser(text ?? "");
            p.Ws();
            var value = p.Value();
            p.Ws();
            if (!p.End) throw new FormatException("JSON: unerwartete Zeichen am Ende");
            return value;
        }

        public static string Serialize(object value)
        {
            var sb = new StringBuilder();
            Write(sb, value);
            return sb.ToString();
        }

        static void Write(StringBuilder sb, object v)
        {
            switch (v)
            {
                case null: sb.Append("null"); break;
                case string s: WriteString(sb, s); break;
                case bool b: sb.Append(b ? "true" : "false"); break;
                case double d: sb.Append(d.ToString("R", CultureInfo.InvariantCulture)); break;
                case float f: sb.Append(((double)f).ToString("R", CultureInfo.InvariantCulture)); break;
                case int or long or short or byte or decimal:
                    sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); break;
                case IDictionary dict:
                    sb.Append('{');
                    bool first = true;
                    foreach (DictionaryEntry e in dict)
                    {
                        if (!first) sb.Append(',');
                        first = false;
                        WriteString(sb, Convert.ToString(e.Key, CultureInfo.InvariantCulture));
                        sb.Append(':');
                        Write(sb, e.Value);
                    }
                    sb.Append('}');
                    break;
                case IEnumerable list:
                    sb.Append('[');
                    bool f1 = true;
                    foreach (var item in list)
                    {
                        if (!f1) sb.Append(',');
                        f1 = false;
                        Write(sb, item);
                    }
                    sb.Append(']');
                    break;
                default: WriteString(sb, Convert.ToString(v, CultureInfo.InvariantCulture)); break;
            }
        }

        static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        sealed class Parser
        {
            readonly string s;
            int i;
            public Parser(string s) { this.s = s; }
            public bool End => i >= s.Length;

            public void Ws() { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

            char Next() => i < s.Length ? s[i++] : throw new FormatException("JSON: unerwartetes Ende");

            public object Value()
            {
                if (End) throw new FormatException("JSON: unerwartetes Ende");
                char c = s[i];
                if (c == '{') return Obj();
                if (c == '[') return Arr();
                if (c == '"') return Str();
                if (c == 't') { Lit("true"); return true; }
                if (c == 'f') { Lit("false"); return false; }
                if (c == 'n') { Lit("null"); return null; }
                return Num();
            }

            void Lit(string word)
            {
                if (string.CompareOrdinal(s, i, word, 0, word.Length) != 0) throw new FormatException("JSON: ungültiger Wert");
                i += word.Length;
            }

            Dictionary<string, object> Obj()
            {
                var d = new Dictionary<string, object>();
                i++;
                Ws();
                if (!End && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws();
                    var key = Str();
                    Ws();
                    if (Next() != ':') throw new FormatException("JSON: ':' erwartet");
                    Ws();
                    d[key] = Value();
                    Ws();
                    var c = Next();
                    if (c == '}') return d;
                    if (c != ',') throw new FormatException("JSON: ',' oder '}' erwartet");
                }
            }

            List<object> Arr()
            {
                var l = new List<object>();
                i++;
                Ws();
                if (!End && s[i] == ']') { i++; return l; }
                while (true)
                {
                    Ws();
                    l.Add(Value());
                    Ws();
                    var c = Next();
                    if (c == ']') return l;
                    if (c != ',') throw new FormatException("JSON: ',' oder ']' erwartet");
                }
            }

            string Str()
            {
                if (Next() != '"') throw new FormatException("JSON: '\"' erwartet");
                var sb = new StringBuilder();
                while (true)
                {
                    char c = Next();
                    if (c == '"') return sb.ToString();
                    if (c != '\\') { sb.Append(c); continue; }
                    c = Next();
                    switch (c)
                    {
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'u':
                            if (i + 4 > s.Length) throw new FormatException("JSON: \\u unvollständig");
                            sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                            i += 4;
                            break;
                        default: sb.Append(c); break;
                    }
                }
            }

            object Num()
            {
                int start = i;
                while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
                if (start == i) throw new FormatException("JSON: ungültiges Zeichen");
                return double.Parse(s.Substring(start, i - start), NumberStyles.Float, CultureInfo.InvariantCulture);
            }
        }
    }

    /// <summary>Bequemer Zugriff auf geparste JSON-Objekte.</summary>
    public static class J
    {
        public static object Get(this Dictionary<string, object> d, string key) =>
            d != null && d.TryGetValue(key, out var v) ? v : null;

        public static string Str(this Dictionary<string, object> d, string key, string fallback = "")
        {
            var v = d.Get(key);
            return v == null ? fallback : v is string s ? s : Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        public static double Num(this Dictionary<string, object> d, string key, double fallback = 0) =>
            d.Get(key) is double x ? x : fallback;

        public static int Int(this Dictionary<string, object> d, string key, int fallback = 0) =>
            d.Get(key) is double x ? (int)x : fallback;

        public static bool Bool(this Dictionary<string, object> d, string key) => d.Get(key) is bool b && b;

        public static Dictionary<string, object> Obj(this Dictionary<string, object> d, string key) =>
            d.Get(key) as Dictionary<string, object> ?? new Dictionary<string, object>();

        public static List<object> List(this Dictionary<string, object> d, string key) =>
            d.Get(key) as List<object> ?? new List<object>();

        public static List<string> Strings(this Dictionary<string, object> d, string key)
        {
            var result = new List<string>();
            foreach (var v in d.List(key)) if (v != null) result.Add(Convert.ToString(v, CultureInfo.InvariantCulture));
            return result;
        }
    }
}
