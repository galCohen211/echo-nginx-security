// Raw HTTP/1.x over TCP. Requests are sent byte-for-byte as given and
// responses are parsed by hand, so header names, order and body bytes are
// compared exactly as nginx sent them.
import net from "node:net";

export interface HttpResponse {
  statusLine: string;
  status: number;
  headers: Array<[string, string]>;
  body: Buffer;
  truncated: boolean;
}

export interface ExchangeResult {
  responses: HttpResponse[];
  // Bytes after the last complete response (should be empty).
  trailing: Buffer;
  socketError?: string;
  timedOut: boolean;
}

export interface ExchangeOptions {
  // Per response, whether it answers a HEAD request (no body follows).
  head?: boolean[];
  timeoutMs?: number;
}

export function rawExchange(
  port: number,
  request: string | Buffer | Array<string | Buffer>,
  opts: ExchangeOptions = {},
): Promise<ExchangeResult> {
  const parts = Array.isArray(request) ? request : [request];
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let socketError: string | undefined;
    let timedOut = false;
    let done = false;
    const sock = net.connect({ host: "127.0.0.1", port });
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      const buf = Buffer.concat(chunks);
      const { responses, rest } = parseResponses(buf, opts.head ?? []);
      resolve({ responses, trailing: rest, socketError, timedOut });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      finish();
    }, opts.timeoutMs ?? 10_000);
    sock.on("connect", () => {
      for (const p of parts) sock.write(p);
    });
    sock.on("data", (d) => chunks.push(d));
    // nginx may reset the connection after an error response while we are
    // still sending (e.g. 413); keep what was received.
    sock.on("error", (e: NodeJS.ErrnoException) => {
      socketError = e.code ?? e.message;
    });
    sock.on("end", finish);
    sock.on("close", finish);
  });
}

export function parseResponses(buf: Buffer, head: boolean[]): { responses: HttpResponse[]; rest: Buffer } {
  const responses: HttpResponse[] = [];
  let off = 0;
  while (off < buf.length) {
    const end = buf.indexOf("\r\n\r\n", off, "latin1");
    if (end < 0) break;
    const lines = buf.subarray(off, end).toString("latin1").split("\r\n");
    const statusLine = lines[0];
    const status = Number(statusLine.split(" ")[1]);
    const headers = lines.slice(1).map((l): [string, string] => {
      const i = l.indexOf(":");
      return [l.slice(0, i), l.slice(i + 1).trim()];
    });
    const get = (n: string) => headers.find(([k]) => k.toLowerCase() === n)?.[1];
    let p = end + 4;
    let body = Buffer.alloc(0);
    let truncated = false;
    const noBody = head[responses.length] || status < 200 || status === 204 || status === 304;
    if (noBody) {
      // nothing
    } else if (get("transfer-encoding")?.toLowerCase() === "chunked") {
      const parts: Buffer[] = [];
      for (;;) {
        const le = buf.indexOf("\r\n", p, "latin1");
        if (le < 0) { truncated = true; p = buf.length; break; }
        const size = parseInt(buf.subarray(p, le).toString("latin1"), 16);
        p = le + 2;
        if (size === 0) {
          const te = buf.indexOf("\r\n", p, "latin1");
          p = te < 0 ? buf.length : te + 2;
          break;
        }
        if (p + size > buf.length) { truncated = true; parts.push(buf.subarray(p)); p = buf.length; break; }
        parts.push(buf.subarray(p, p + size));
        p += size + 2;
      }
      body = Buffer.concat(parts);
    } else if (get("content-length") !== undefined) {
      const len = Number(get("content-length"));
      truncated = p + len > buf.length;
      body = buf.subarray(p, Math.min(p + len, buf.length));
      p = Math.min(p + len, buf.length);
    } else {
      body = buf.subarray(p);
      p = buf.length;
    }
    responses.push({ statusLine, status, headers, body, truncated });
    off = p;
  }
  return { responses, rest: buf.subarray(off) };
}

// A request with Host: localhost and Connection: close unless overridden.
export function request(
  method: string,
  path: string,
  headers: Record<string, string> = {},
  version = "HTTP/1.1",
): string {
  const h: Record<string, string> = { Host: "localhost", Connection: "close", ...headers };
  const lines = Object.entries(h)
    .filter(([, v]) => v !== "")
    .map(([k, v]) => `${k}: ${v}\r\n`)
    .join("");
  return `${method} ${path} ${version}\r\n${lines}\r\n`;
}
