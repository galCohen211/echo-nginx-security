# Compatibility test

Checks that `echo-nginx:1.25.5` is a drop-in replacement for
`nginx:1.25-bookworm`. TypeScript, Node.js built-ins only at runtime
(`typescript` and `@types/node` are build-time dev dependencies).

```sh
make test            # from the repo root: builds the .deb and image if needed, then runs the test
```

`make test` calls `node test/scripts/run.cjs`, which checks Node 20+ and
Docker, pulls the upstream image if missing, then runs `npm ci`, the build and
the test. That logic lives in Node rather than the Makefile so the target works
with both cmd.exe (Windows GNU Make) and sh. With both images already present,
the runner can be called directly from the repo root:

```sh
node test/scripts/run.cjs [--upstream nginx:1.25-bookworm] [--candidate echo-nginx:1.25.5]
```

Requires Node.js 20+ and Docker. `UPSTREAM_IMAGE` / `CANDIDATE_IMAGE` override
the two images. Exit code: `0` = all checks passed, `1` = a difference or
failed check, `2` = setup error (missing image, container not ready, ...).

## What "working correctly" means

For every request below, the new image must answer **byte-for-byte like the
upstream image**:

- the same status line
- the same headers, with the same names (case included), values and order
- the same body bytes (chunked bodies are compared after de-chunking)
- the same number of responses on the connection and the same way the
  connection ends

The only exception is `Date` (see below). Each scenario also states the status
code it expects, so a scenario still fails if both images give the same wrong
answer (for example if a 413 test never actually triggered the limit).

## How it runs

1. Generates the served files in `test/.work/srv/` (gitignored), all with the
   same fixed mtime: a 5 MiB pseudo-random file, a small valid MP4 and a
   crafted MP4 (built in code, no binaries in the repo), plus
   `fixtures/static/hello.txt`.
2. Starts one container per image (`docker run --rm`). Ports 80 and 8080 are
   published on `127.0.0.1`, with Docker picking free host ports. Both mount the
   same `fixtures/compat.conf` (as `/etc/nginx/conf.d/compat.conf`) and the
   same `/srv/compat`.
3. Waits until both answer `GET /` on port 80 and `GET /header` on port 8080
   with 200.
4. Sends every request to both over raw TCP sockets, so malformed requests
   reach nginx unchanged and responses are compared as sent, then prints a
   diff for anything that differs.
5. Removes both containers in every case: success, failure, exception, Ctrl+C.

## Scenarios

| ID | Request | Expected |
|----|---------|----------|
| `default-get` | `GET /` (default page) | 200 |
| `default-head` | `HEAD /` | 200, no body |
| `default-404` | `GET /does-not-exist.html` | 404 |
| `default-50x` | `GET /50x.html` | 200 |
| `default-if-modified-since` | `GET /` with a non-matching `If-Modified-Since` (`if_modified_since exact`) | 200 |
| `custom-header` | location with `add_header X-Compat-Test` | 200 + header |
| `custom-redirect` | `return 301 /static/hello.txt` | 301 + `Location` |
| `custom-json` | `return 200` with `default_type application/json` | 200 |
| `custom-static` | small static file | 200 |
| `custom-gzip` | same file with `Accept-Encoding: gzip` (`gzip on`) | 200, gzip body |
| `custom-not-modified` | `If-Modified-Since` = the file's mtime | 304 |
| `body-too-large` | `POST /` with a 2 MiB body (> default `client_max_body_size 1m`) | 413 |
| `large-file` | `GET` 5 MiB static file | 200 |
| `large-range` | `Range: bytes=1048576-1049599` | 206 |
| `large-range-suffix` | `Range: bytes=-512` | 206 |
| `large-range-invalid` | `Range: bytes=99999999-` | 416 |
| `malformed-request-line` | `GARBAGE` | 400 |
| `malformed-version` | `GET / HTTP/9.9` | 505 |
| `malformed-big-header` | 16 KiB header (> `large_client_header_buffers 4 8k`) | 400 |
| `malformed-no-host` | HTTP/1.1 without `Host` | 400 |
| `http10` | `GET / HTTP/1.0` without `Host` | 200 |
| `keep-alive` | two pipelined requests on one keep-alive connection | 200, 200 |
| `mp4-plain` | `.mp4` without arguments (`mp4;` location) | 200 |
| `mp4-start` | `.mp4?start=4.5` (module rewrites the sample tables) | 200 |
| `mp4-start-end` | `.mp4?start=2&end=8` | 200 |
| `mp4-start-beyond` | `.mp4?start=60` (past the end; nginx 1.25.5 answers 500) | 500 |

### Backport check (expected difference)

`cve-2024-7347` requests a crafted MP4 whose `stsc` table goes backwards
(first_chunk 3 → 2) with `?start=6`. This is the case fixed by the
CVE-2024-7347 patch, so the images are **meant** to differ here. The test
only asserts the patched image: it must answer 500 and log
`unordered mp4 stsc chunks`. The upstream result is printed for reference.
In our run, upstream processed the file and answered 200, which is the
vulnerable code path running without complaint.

## Normalized headers

| Header | Why it differs | How it is checked |
|--------|----------------|-------------------|
| `Date` | Set from each server's clock when the response is sent; two containers cannot produce the same value. | Must appear exactly once in both responses, be a valid HTTP date, and differ by at most 120 s. Only then is the value replaced by `<checked>` for the comparison. |

No other header is excluded or normalized:

- **`ETag` / `Last-Modified` on the mounted files** are identical because both
  containers serve the same bind mount, and the generator sets one fixed mtime
  on every file.
- **`ETag` / `Last-Modified` on the default page and `50x.html`** (files from
  the nginx package) are identical too, because the package build preserves the
  timestamps of the upstream source tarball. The cause is fixed rather than
  masked.
- **`Server: nginx/1.25.5`** is identical (same version, `server_tokens` on).

## What the test does not cover

- **HTTPS / TLS, HTTP/2 and HTTP/3.** The default config has no TLS server,
  so the OpenSSL bump is not exercised here.
- **The dynamic modules** (geoip, image-filter, njs, xslt). They are
  deliberately absent from the new image; a config with `load_module` for them
  would fail on the new image and is not tested.
- **Proxying, FastCGI/uWSGI/SCGI, the mail and stream modules, caching,
  rate limiting, auth** and most other directives. Only the default config
  plus `fixtures/compat.conf` are used.
- **Entrypoint features driven by environment variables** (`/etc/nginx/templates`
  with envsubst, `NGINX_ENTRYPOINT_*`, local resolvers). Both images use
  byte-identical scripts, but the test does not run them with options set.
- **Performance, concurrency, memory use, long-running stability and
  signal/reload behaviour** (`nginx -s reload`, `SIGQUIT` graceful stop).
- **Timing-dependent behaviour** such as timeouts and slow clients.
- **True sequential keep-alive.** The keep-alive scenario pipelines both
  requests on one connection.
- **Exhaustive fuzzing.** The malformed requests are a handful of fixed cases.
- **Non-amd64 architectures.**
