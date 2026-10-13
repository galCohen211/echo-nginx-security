// Requests sent identically to both images. `expect` lists the status code
// expected for each response, so a scenario also fails if both images agree
// but the request did not exercise what it was meant to.
import { FIXED_MTIME } from "./fixtures.js";
import { request } from "./http.js";

export interface Scenario {
  id: string;
  title: string;
  port: "default" | "custom";
  send: string | Buffer | Array<string | Buffer>;
  expect: number[];
  head?: boolean[];
  // nginx may reset the socket while we are still sending a body it has
  // already rejected; whether the reset is seen is timing-dependent.
  tolerateSocketError?: boolean;
}

const MiB = 1024 * 1024;
const bigBody = Buffer.alloc(2 * MiB, "a");

export const SCENARIOS: Scenario[] = [
  // default server (default.conf, port 80)
  { id: "default-get", title: "GET / (default page)", port: "default", send: request("GET", "/"), expect: [200] },
  { id: "default-head", title: "HEAD /", port: "default", send: request("HEAD", "/"), expect: [200], head: [true] },
  { id: "default-404", title: "GET missing file", port: "default", send: request("GET", "/does-not-exist.html"), expect: [404] },
  { id: "default-50x", title: "GET /50x.html", port: "default", send: request("GET", "/50x.html"), expect: [200] },
  {
    // if_modified_since defaults to "exact": only an exact match gives 304.
    id: "default-if-modified-since",
    title: "GET / with non-matching If-Modified-Since (exact mode)",
    port: "default",
    send: request("GET", "/", { "If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT" }),
    expect: [200],
  },

  // custom config (test/fixtures/compat.conf, port 8080)
  { id: "custom-header", title: "location with add_header", port: "custom", send: request("GET", "/header"), expect: [200] },
  { id: "custom-redirect", title: "return 301", port: "custom", send: request("GET", "/redirect"), expect: [301] },
  { id: "custom-json", title: "return 200 with default_type", port: "custom", send: request("GET", "/json"), expect: [200] },
  { id: "custom-static", title: "small static file", port: "custom", send: request("GET", "/static/hello.txt"), expect: [200] },
  {
    id: "custom-gzip",
    title: "small static file with Accept-Encoding: gzip",
    port: "custom",
    send: request("GET", "/static/hello.txt", { "Accept-Encoding": "gzip" }),
    expect: [200],
  },
  {
    id: "custom-not-modified",
    title: "static file with If-Modified-Since = its mtime",
    port: "custom",
    send: request("GET", "/static/hello.txt", { "If-Modified-Since": FIXED_MTIME.toUTCString() }),
    expect: [304],
  },

  // request body limit (default client_max_body_size 1m)
  {
    id: "body-too-large",
    title: "POST 2 MiB body (> client_max_body_size)",
    port: "default",
    send: [request("POST", "/", { "Content-Type": "application/octet-stream", "Content-Length": String(bigBody.length) }), bigBody],
    expect: [413],
    tolerateSocketError: true,
  },

  // large response
  { id: "large-file", title: "GET 5 MiB static file", port: "custom", send: request("GET", "/large/blob.bin"), expect: [200] },
  {
    id: "large-range",
    title: "Range: bytes=1048576-1049599",
    port: "custom",
    send: request("GET", "/large/blob.bin", { Range: "bytes=1048576-1049599" }),
    expect: [206],
  },
  {
    id: "large-range-suffix",
    title: "Range: bytes=-512 (suffix)",
    port: "custom",
    send: request("GET", "/large/blob.bin", { Range: "bytes=-512" }),
    expect: [206],
  },
  {
    id: "large-range-invalid",
    title: "Range beyond end of file",
    port: "custom",
    send: request("GET", "/large/blob.bin", { Range: "bytes=99999999-" }),
    expect: [416],
  },

  // malformed requests (raw TCP)
  { id: "malformed-request-line", title: "bad request line", port: "default", send: "GARBAGE\r\n\r\n", expect: [400] },
  {
    id: "malformed-version",
    title: "invalid HTTP version (HTTP/9.9)",
    port: "default",
    send: "GET / HTTP/9.9\r\nHost: localhost\r\n\r\n",
    expect: [505],
  },
  {
    id: "malformed-big-header",
    title: "16 KiB header (> large_client_header_buffers)",
    port: "default",
    send: request("GET", "/", { "X-Large": "a".repeat(16 * 1024) }),
    expect: [400],
  },
  {
    id: "malformed-no-host",
    title: "HTTP/1.1 without Host",
    port: "default",
    send: "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
    expect: [400],
  },

  // protocol versions / connection handling
  { id: "http10", title: "HTTP/1.0 request without Host", port: "default", send: "GET / HTTP/1.0\r\n\r\n", expect: [200] },
  {
    id: "keep-alive",
    title: "two requests on one keep-alive connection",
    port: "default",
    send: [request("GET", "/", { Connection: "keep-alive" }) + request("GET", "/50x.html")],
    expect: [200, 200],
  },

  // mp4 module (the module patched for CVE-2024-7347)
  { id: "mp4-plain", title: "GET .mp4 without arguments", port: "custom", send: request("GET", "/media/sample.mp4"), expect: [200] },
  {
    id: "mp4-start",
    title: "GET .mp4?start=4.5 (crops sample tables)",
    port: "custom",
    send: request("GET", "/media/sample.mp4?start=4.5"),
    expect: [200],
  },
  {
    id: "mp4-start-end",
    title: "GET .mp4?start=2&end=8",
    port: "custom",
    send: request("GET", "/media/sample.mp4?start=2&end=8"),
    expect: [200],
  },
  {
    // nginx 1.25.5 treats a start time past the last sample as an error (500).
    id: "mp4-start-beyond",
    title: "GET .mp4?start=60 (past the end)",
    port: "custom",
    send: request("GET", "/media/sample.mp4?start=60"),
    expect: [500],
  },
];

// Not a compatibility check: the backported fix is supposed to change
// behaviour here. Reported separately; only the patched image is asserted.
export const CVE_2024_7347: Scenario = {
  id: "cve-2024-7347",
  title: "crafted .mp4 with unordered stsc chunks, ?start=6",
  port: "custom",
  send: request("GET", "/media/cve-2024-7347.mp4?start=6"),
  expect: [500],
};
export const CVE_2024_7347_LOG = "unordered mp4 stsc chunks";
