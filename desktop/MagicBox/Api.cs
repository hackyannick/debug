using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MagicBox.Desktop
{
    public sealed class ApiException : Exception
    {
        public int Status { get; }
        public string Mode { get; }
        public ApiException(int status, string message, string mode = "") : base(message)
        {
            Status = status;
            Mode = mode;
        }
        public bool NeedsLogin => Status == 401;
    }

    /// <summary>REST-Client für den Magic-Box-Server (alle Aufrufe mit „Authorization: Bearer“).</summary>
    public sealed class ApiClient : IDisposable
    {
        readonly HttpClient http;
        readonly HttpClient longHttp; // Uploads und Live-Ereignisse: ohne Zeitlimit
        public string BaseUrl { get; }
        public string Token { get; set; } = "";

        public ApiClient(string baseUrl)
        {
            BaseUrl = Normalize(baseUrl);
            http = new HttpClient { Timeout = TimeSpan.FromSeconds(100) };
            longHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
            foreach (var c in new[] { http, longHttp })
                c.DefaultRequestHeaders.UserAgent.ParseAdd($"MagicBox-Desktop/{Program.Version}");
        }

        public static string Normalize(string url)
        {
            url = (url ?? "").Trim().TrimEnd('/');
            if (url.Length > 0 && !url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                url = "https://" + url;
            return url;
        }

        public HttpRequestMessage Request(HttpMethod method, string path)
        {
            var req = new HttpRequestMessage(method, BaseUrl + path);
            req.Headers.Add("X-MagicBox", "1"); // Schutz gegen Cross-Site-Anfragen (verlangt der Server)
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrEmpty(Token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            return req;
        }

        static async Task<string> Check(HttpResponseMessage res)
        {
            var text = res.Content == null ? "" : await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (res.IsSuccessStatusCode) return text;
            string message = $"HTTP {(int)res.StatusCode} {res.ReasonPhrase}", mode = "";
            try
            {
                if (Json.Parse(text) is Dictionary<string, object> d)
                {
                    message = d.Str("error", message);
                    mode = d.Str("mode");
                }
            }
            catch (FormatException)
            {
                if (text.Contains("<title>")) message += " (Antwort ist eine HTML-Seite – Proxy/Anmeldung dazwischen?)";
            }
            throw new ApiException((int)res.StatusCode, message, mode);
        }

        async Task<string> Send(HttpRequestMessage req, HttpClient client = null, CancellationToken ct = default)
        {
            try
            {
                using (req)
                using (var res = await (client ?? http).SendAsync(req, ct).ConfigureAwait(false))
                    return await Check(res).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new ApiException(0, "Server nicht erreichbar: " + Inner(ex));
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new ApiException(0, "Zeitüberschreitung – der Server antwortet nicht.");
            }
        }

        static string Inner(Exception ex)
        {
            while (ex.InnerException != null) ex = ex.InnerException;
            return ex.Message;
        }

        public async Task<object> Call(HttpMethod method, string path, object body = null)
        {
            var req = Request(method, path);
            if (body != null)
                req.Content = new StringContent(MagicBox.Desktop.Json.Serialize(body), Encoding.UTF8, "application/json");
            var text = await Send(req).ConfigureAwait(false);
            return string.IsNullOrEmpty(text) ? null : MagicBox.Desktop.Json.Parse(text);
        }

        public async Task<Dictionary<string, object>> Obj(HttpMethod method, string path, object body = null) =>
            await Call(method, path, body).ConfigureAwait(false) as Dictionary<string, object> ?? new Dictionary<string, object>();

        public Task<Dictionary<string, object>> Get(string path) => Obj(HttpMethod.Get, path);
        public Task<Dictionary<string, object>> Post(string path, object body = null) => Obj(HttpMethod.Post, path, body);

        public Task<string> Text(string path) => Send(Request(HttpMethod.Get, path));

        public async Task<byte[]> Bytes(string path)
        {
            try
            {
                using (var req = Request(HttpMethod.Get, path))
                using (var res = await longHttp.SendAsync(req).ConfigureAwait(false))
                {
                    if (!res.IsSuccessStatusCode) await Check(res).ConfigureAwait(false);
                    return await res.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                }
            }
            catch (HttpRequestException ex)
            {
                throw new ApiException(0, "Server nicht erreichbar: " + Inner(ex));
            }
        }

        // ------------------------------------------------------------------ Aufträge
        public async Task<List<Dictionary<string, object>>> Jobs()
        {
            var list = new List<Dictionary<string, object>>();
            if (await Call(HttpMethod.Get, "/api/jobs").ConfigureAwait(false) is List<object> raw)
                foreach (var item in raw)
                    if (item is Dictionary<string, object> d) list.Add(d);
            return list;
        }

        public async Task<Dictionary<string, object>> Upload(string file, string profile, string password, string question,
            IProgress<double> progress, CancellationToken ct)
        {
            var q = new List<string> { "name=" + Uri.EscapeDataString(Path.GetFileName(file)), "profile=" + Uri.EscapeDataString(profile) };
            if (!string.IsNullOrEmpty(password)) q.Add("password=" + Uri.EscapeDataString(password));
            if (!string.IsNullOrEmpty(question)) q.Add("question=" + Uri.EscapeDataString(question));
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, true))
            {
                var req = Request(HttpMethod.Post, "/api/jobs?" + string.Join("&", q));
                req.Content = new StreamContent(new ProgressStream(fs, progress), 1 << 16);
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                req.Content.Headers.ContentLength = fs.Length;
                var text = await Send(req, longHttp, ct).ConfigureAwait(false);
                return MagicBox.Desktop.Json.Parse(text) as Dictionary<string, object>;
            }
        }

        // ------------------------------------------------------------------ Anmeldung
        public Task<Dictionary<string, object>> AuthInfo() => Get("/auth/info");

        public Task<Dictionary<string, object>> Exchange(string code, string verifier) =>
            Post("/auth/desktop/token", new Dictionary<string, object>
                { ["code"] = code, ["verifier"] = verifier, ["label"] = Environment.MachineName });

        public void Dispose()
        {
            http.Dispose();
            longHttp.Dispose();
        }
    }

    /// <summary>Meldet den Fortschritt beim Lesen (Upload) – Länge und Position bleiben erhalten (Content-Length).</summary>
    sealed class ProgressStream : Stream
    {
        readonly Stream inner;
        readonly IProgress<double> progress;
        long lastReport;
        public ProgressStream(Stream inner, IProgress<double> progress) { this.inner = inner; this.progress = progress; }
        public override bool CanRead => true;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            Report();
            return n;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            int n = await inner.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
            Report();
            return n;
        }

        void Report()
        {
            if (progress == null || inner.Length == 0) return;
            if (inner.Position - lastReport < 256 * 1024 && inner.Position < inner.Length) return;
            lastReport = inner.Position;
            progress.Report((double)inner.Position / inner.Length);
        }
    }

    /// <summary>Live-Ereignisse (Server-Sent Events von /api/events) in einem Hintergrund-Thread,
    /// mit automatischem Neuverbinden.</summary>
    public sealed class EventStream : IDisposable
    {
        readonly ApiClient api;
        readonly Action<Dictionary<string, object>> onEvent;
        readonly Action<bool> onConnected;
        readonly CancellationTokenSource cts = new CancellationTokenSource();
        readonly HttpClient client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };

        public EventStream(ApiClient api, Action<Dictionary<string, object>> onEvent, Action<bool> onConnected)
        {
            this.api = api;
            this.onEvent = onEvent;
            this.onConnected = onConnected;
            var t = new Thread(Run) { IsBackground = true, Name = "MagicBox-Events" };
            t.Start();
        }

        void Run()
        {
            while (!cts.IsCancellationRequested)
            {
                bool connected = false;
                try
                {
                    var req = api.Request(HttpMethod.Get, "/api/events");
                    req.Headers.Accept.Clear();
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
                    using (var res = client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).Result)
                    {
                        if (!res.IsSuccessStatusCode)
                        {
                            if ((int)res.StatusCode == 401) onEvent(new Dictionary<string, object> { ["type"] = "unauthorized" });
                            throw new IOException("HTTP " + (int)res.StatusCode);
                        }
                        connected = true;
                        onConnected(true);
                        using (var stream = res.Content.ReadAsStreamAsync().Result)
                        using (var reader = new StreamReader(stream, Encoding.UTF8))
                        {
                            var data = new StringBuilder();
                            using (cts.Token.Register(() => { try { stream.Dispose(); } catch (Exception) { } }))
                            {
                                string line;
                                while (!cts.IsCancellationRequested && (line = reader.ReadLine()) != null)
                                {
                                    if (line.StartsWith("data:"))
                                    {
                                        if (data.Length > 0) data.Append('\n');
                                        data.Append(line.Substring(5).TrimStart(' '));
                                    }
                                    else if (line.Length == 0 && data.Length > 0)
                                    {
                                        Dispatch(data.ToString());
                                        data.Clear();
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // Verbindung weg – unten kurz warten und neu verbinden
                }
                if (cts.IsCancellationRequested) break;
                if (connected) onConnected(false);
                cts.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(connected ? 1 : 3));
            }
        }

        void Dispatch(string payload)
        {
            try
            {
                if (Json.Parse(payload) is Dictionary<string, object> d) onEvent(d);
            }
            catch (FormatException)
            {
            }
        }

        public void Dispose()
        {
            cts.Cancel();
            client.Dispose();
        }
    }
}
