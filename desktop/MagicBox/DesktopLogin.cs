using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MagicBox.Desktop
{
    /// <summary>Anmeldung über den System-Browser (RFC 8252): Die App lauscht kurz auf 127.0.0.1,
    /// der Browser meldet sich bei Ory an (Captcha, 2FA) und schickt einen Einmal-Code zurück,
    /// den die App per PKCE gegen ein API-Token tauscht.</summary>
    public static class DesktopLogin
    {
        public static string B64Url(byte[] data) =>
            Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        static string Random(int bytes)
        {
            var b = new byte[bytes];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return B64Url(b);
        }

        public static async Task<Dictionary<string, object>> Run(ApiClient api, CancellationToken ct)
        {
            string verifier = Random(32), state = Random(16);
            string challenge;
            using (var sha = SHA256.Create()) challenge = B64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                var url = $"{api.BaseUrl}/auth/desktop?port={port}&state={state}&challenge={challenge}";
                if (!Program.OpenUrl(url))
                    throw new ApiException(0, "Der Browser ließ sich nicht öffnen. Bitte diese Adresse im Browser aufrufen:\n" + url);

                using (ct.Register(() => listener.Stop()))
                {
                    while (true)
                    {
                        TcpClient client;
                        try
                        {
                            client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        }
                        catch (Exception) when (ct.IsCancellationRequested)
                        {
                            throw new OperationCanceledException(ct);
                        }
                        var query = await HandleOne(client, state).ConfigureAwait(false);
                        if (query == null) continue; // z. B. /favicon.ico
                        if (query.TryGetValue("error", out var error))
                            throw new ApiException(403, error == "access_denied"
                                ? "Die Anmeldung wurde im Browser abgelehnt."
                                : "Anmeldung fehlgeschlagen: " + error);
                        return await api.Exchange(query["code"], verifier).ConfigureAwait(false);
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        /// <summary>Beantwortet eine Anfrage des Browsers; liefert die Parameter von /callback (sonst null).</summary>
        static async Task<Dictionary<string, string>> HandleOne(TcpClient client, string expectedState)
        {
            using (client)
            {
                client.ReceiveTimeout = 5000;
                var stream = client.GetStream();
                var reader = new StreamReader(stream, Encoding.ASCII);
                var requestLine = await reader.ReadLineAsync().ConfigureAwait(false) ?? "";
                string line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync().ConfigureAwait(false))) { }

                var parts = requestLine.Split(' ');
                var target = parts.Length > 1 ? parts[1] : "";
                if (!target.StartsWith("/callback?"))
                {
                    await Respond(stream, 404, "Nicht gefunden", "").ConfigureAwait(false);
                    return null;
                }
                var query = new Dictionary<string, string>();
                foreach (var pair in target.Substring("/callback?".Length).Split('&'))
                {
                    var kv = pair.Split(new[] { '=' }, 2);
                    if (kv.Length == 2) query[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1].Replace('+', ' '));
                }
                bool stateOk = query.TryGetValue("state", out var st) && st == expectedState;
                bool ok = stateOk && query.ContainsKey("code");
                await Respond(stream, ok ? 200 : 400,
                    ok ? "Anmeldung abgeschlossen" : "Anmeldung nicht abgeschlossen",
                    ok ? "Du kannst dieses Browserfenster schließen und zur Magic Box zurückkehren."
                       : "Die Anmeldung wurde abgebrochen. Bitte in der Magic Box erneut starten.").ConfigureAwait(false);
                if (!stateOk) return null; // fremde oder veraltete Anfrage ignorieren
                if (!ok && !query.ContainsKey("error")) query["error"] = "kein Anmeldecode erhalten";
                return query;
            }
        }

        static async Task Respond(Stream stream, int status, string title, string text)
        {
            var html = "<!doctype html><meta charset='utf-8'><title>Magic Box</title>" +
                       "<body style=\"font:10pt Tahoma,sans-serif;background:#c3daf9;margin:0;padding:40px\">" +
                       "<div style='max-width:460px;margin:auto;background:#fff;border:1px solid #6593cf'>" +
                       "<div style='padding:8px 12px;color:#fff;font-weight:bold;" +
                       "background:linear-gradient(#5987d6,#033893)'>Magic Box</div>" +
                       $"<div style='padding:14px 12px'><b>{WebUtility.HtmlEncode(title)}</b><p>{WebUtility.HtmlEncode(text)}</p></div>" +
                       "</div></body>";
            var body = Encoding.UTF8.GetBytes(html);
            var head = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status} {(status == 200 ? "OK" : "Error")}\r\nContent-Type: text/html; charset=utf-8\r\n" +
                $"Content-Length: {body.Length}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n");
            await stream.WriteAsync(head, 0, head.Length).ConfigureAwait(false);
            await stream.WriteAsync(body, 0, body.Length).ConfigureAwait(false);
        }
    }
}
