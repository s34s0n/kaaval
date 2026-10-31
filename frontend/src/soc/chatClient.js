// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Stream POST /api/chat (SSE-over-POST) — EventSource can't POST, so we read
// the response body and parse `event:`/`data:` frames manually.
export async function streamChat({ message, history = [], incidentId, plain = true, signal,
                                   onThink, onTool, onToken, onActions, onDone }) {
  const resp = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history, incident_id: incidentId, plain }),
    signal,
  });
  // A non-2xx returns an error body (HTML/JSON), not an SSE stream — surface the
  // real status instead of parsing it as empty frames and hanging on "…".
  if (!resp.ok || !resp.body) {
    throw new Error(`chat backend returned HTTP ${resp.status}`);
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) !== -1) {
      const frame = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let ev = "message", data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) ev = line.slice(6).trim();
        else if (line.startsWith("data:")) data += line.slice(5).trim();
      }
      if (!data) continue;
      let payload;
      try { payload = JSON.parse(data); } catch { continue; }
      if (ev === "think") onThink?.(payload.t || "");
      else if (ev === "token") onToken?.(payload.t || "");
      else if (ev === "tool") onTool?.(payload);
      else if (ev === "actions") onActions?.(payload.proposed || []);
      else if (ev === "done") onDone?.(payload);
    }
  }
  onDone?.({ ok: true });
}
