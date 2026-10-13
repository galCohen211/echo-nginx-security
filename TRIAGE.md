# Triage

Target image: `nginx:1.25-bookworm` (nginx 1.25.5, Debian 12.5).
Evidence: `reports/baseline-trivy.json` (Trivy 0.74.0), `reports/baseline-grype.json`
(Grype 0.119.0), `reports/upstream-nginx-V.txt`, nginx.org security advisories
(checked 2026-10-13). Scanner and DB versions: `reports/scan-info.md`.

## Selected fixes

| # | Fix method | Target | CVEs addressed | Verified by |
|---|-----------|--------|----------------|-------------|
| 1 | Version bump | `libssl3` + `openssl` 3.0.11-1~deb12u2 → **3.0.22-1~deb12u1** | CVE-2024-6119, CVE-2025-15467 (+ all other fixable OpenSSL findings) | Scanner diff (both scanners) |
| 2 | Source backport | nginx 1.25.5 + nginx.org patch | **CVE-2024-7347** | Patch applied in build + mp4 test; **not** visible in scanner diff |
| – | Backup backport (documented only) | nginx 1.25.5 | CVE-2025-53859 | – |

### 1. Version bump: OpenSSL → 3.0.22-1~deb12u1

nginx links OpenSSL dynamically: `nginx -V` says *"built with OpenSSL 3.0.9 …
(running with OpenSSL 3.0.11 19 Sep 2023)"*, and `ldd /usr/sbin/nginx` shows
`libssl.so.3` / `libcrypto.so.3`. Updating the Debian package fixes the library
nginx uses for every TLS connection, without changing nginx itself.

`3.0.22-1~deb12u1` is the highest fixed version for `libssl3` in either report,
so it covers every OpenSSL finding that has a Debian fix.

**Cited CVEs:**

| CVE | Trivy | Grype | Fixed in | Why it matters here |
|-----|-------|-------|----------|---------------------|
| **CVE-2024-6119** | HIGH | High (EPSS 0.67) | 3.0.14-1~deb12u2 | Denial of service in X.509 name checks during certificate verification. Reachable when nginx verifies certificates (client certs via `ssl_verify_client`, upstream TLS via `proxy_ssl_verify`). |
| **CVE-2025-15467** | HIGH | Critical (EPSS 0.52) | 3.0.18-1~deb12u2 | Highest-rated OpenSSL finding fixed by the bump (remote code execution or DoS). The vulnerable code is in OpenSSL's CMS parsing, which nginx's TLS path does not normally use, so the main exposure is through other OpenSSL users in the image (e.g. the `openssl` CLI). |

**Effect on the baseline:** Critical/High findings on `libssl3`: Trivy 10 → 1,
Grype 25 → 1. The same applies to `openssl`. The finding that remains is
CVE-2026-84782, which has no Debian fix.

**Not cited:** CVE-2026-31789 (Critical in both scanners) is a heap overflow
that affects **32-bit systems only**. The image is amd64, so it is fixed by the
bump but not counted as a real risk.

### 2. Source backport: CVE-2024-7347 (ngx_http_mp4_module)

From <https://nginx.org/en/security_advisories.html>:

> **Buffer overread in the ngx_http_mp4_module**
> Severity: low
> Advisory: <https://mailman.nginx.org/pipermail/nginx-announce/2024/UUOCLLONPR6244YQYU65PO5LB7JDYCWM.html>
> CVE-2024-7347
> Not vulnerable: 1.27.1+, 1.26.2+
> Vulnerable: 1.5.13-1.27.0

- **Official patch:** <https://nginx.org/download/patch.2024.mp4.txt>
  (PGP signature: <https://nginx.org/download/patch.2024.mp4.txt.asc>)
- **Affected:** 1.25.5 is in the vulnerable range, and the image is built with
  `--with-http_mp4_module` (see `reports/upstream-nginx-V.txt`).
- **Exposure:** only when the `mp4` directive is enabled and an attacker can get
  a crafted MP4 file served. The impact is a worker crash or memory read
  (nginx.org rates it "low").
- **Plan:** verify the PGP signature and check that the patch applies cleanly to
  the 1.25.5 source. Store it in `build/patches/` and rebuild with the identical
  configure arguments from `reports/upstream-nginx-V.txt`.
- **Why this one:** a small, self-contained upstream patch to a single module,
  for a module the image really compiles in. It shows a real source backport
  without changing the nginx version.

### Backup backport candidate: CVE-2025-53859 (ngx_mail_smtp_module)

Documented only; to be used if the mp4 patch cannot be applied to 1.25.5.

> **Buffer overread in the ngx_mail_smtp_module**
> Severity: low
> CVE-2025-53859
> Not vulnerable: 1.29.1+
> Vulnerable: 0.7.22-1.29.0

- Affected: the image is built with `--with-mail --with-mail_ssl_module`.
- Exploitable only with specific mail-proxy SMTP authentication setups; the default
  image config does not enable the mail proxy at all. Details: F5 article
  <https://my.f5.com/manage/s/article/K000152786>.
- The advisories page links **no patch** for this CVE. A file
  `https://nginx.org/download/patch.2025.smtp.txt` exists on nginx.org but is
  not linked from the advisory. Its content and signature would need checking
  before use.

## Scanner gap for nginx

The nginx and `nginx-module-*` packages come from the nginx.org repository
(maintainer `NGINX Packaging <nginx-packaging@f5.com>`), not from Debian.
Neither scanner checks them against nginx.org's own advisories:

- **Trivy 0.74.0** reports **no** findings on nginx. (Trivy 0.58.1 reported 3,
  so newer Trivy appears to skip this third-party package.)
- **Grype** reports 3 (CVE-2023-44487 High, CVE-2013-0337 Low,
  CVE-2009-4487 Negligible), matched **by package name only** against Debian's
  records for Debian's nginx (`versionConstraint: none (unknown)`).
- Neither reports CVE-2024-7347.

**Consequence:** the backport will **not** show up as a diff between baseline and
final scans. Evidence for it has to come from the build (patch file + signature
check + build log) and a functional test of the mp4 module, documented in the
CVE table in the README.

## Overview: top vulnerable packages

Counts are Critical+High findings / of which a fixed version exists,
from the baseline JSON reports.

| Package | Installed | Trivy C+H (fixable) | Grype C+H (fixable) | Pulled in by | Action |
|---------|-----------|--------------------:|--------------------:|--------------|--------|
| `libssl3`, `openssl` | 3.0.11-1~deb12u2 | 10 (9) each | 25 (24) each | nginx core, njs, curl, `ca-certificates` | **Bump** → 3.0.22-1~deb12u1 |
| `nginx` | 1.25.5-1~bookworm | 0 | 1 (0) | – | **Backport** CVE-2024-7347 |
| `libxml2` | 2.9.14+dfsg-1.3~deb12u1 | 16 (9) | 18 (11) | njs, xslt modules | Leave for now |
| `libexpat1` | 2.5.0-1 | 12 (11) | 14 (12) | fontconfig → image-filter module | Leave for now |
| `perl-base` | 5.36.0-7+deb12u1 | 10 (9) | 14 (12) | Debian base (Essential), not used by nginx | Leave for now |
| `libgnutls30` | 3.7.9-2+deb12u2 | 9 (7) | 11 (11) | apt, LDAP/RTMP (curl) | Leave for now |
| `libc6`, `libc-bin` | 2.36-9+deb12u7 | 0 | 10 (6) each | everything | Leave for now |
| `libpng16-16` | 1.6.39-2 | 6 (6) | 8 (8) | libgd3 → image-filter module | Leave for now |
| `libaom3` | 3.6.0-1 | 7 (5) | 7 (5) | libheif/libavif → image-filter module | Leave for now |
| `libtiff6` | 4.5.0-6+deb12u1 | 8 (4) | 7 (4) | libgd3 → image-filter module | Leave for now |
| Kerberos (`libkrb5-3`, `libk5crypto3`, `libgssapi-krb5-2`, `libkrb5support0`) | 1.20.1-2+deb12u1 | 4 (4) each | 5–6 (5) each | curl (GSSAPI) | Leave for now |
| `libpcre2-8-0` | 10.42-1 | 4 (4) | 4 (4) | nginx core, njs, grep | Leave for now |
| `libssh2-1` | 1.10.0-3+b1 | 2 (2) | 5 (5) | curl | Leave for now |
| `zlib1g` | 1.2.13.dfsg-1 | 1 (0) | 1 (0) | nginx core, everything | Leave: CVE-2023-45853, Debian "will not fix" |

"Leave for now" means not part of the selected fixes. Nearly all of these
have Debian 12 fixes, and many are pulled in only by the dynamic modules
(image-filter, xslt, njs) or by tools nginx doesn't need at runtime (curl,
apt, perl), so a later decision on the final image's contents may remove them.
That decision belongs to the build step, not this triage.

## Residual risk notes for later

- **nginx 1.25.5 is far behind upstream.** nginx.org lists **24 advisories**
  whose vulnerable range includes 1.25.5. The backport fixes one. Others include:
  - **CVE-2026-42533**: buffer overflow when using `map` and regex, rated
    **major**, fixed in 1.30.4/1.31.3.
  - The four 2024 HTTP/3 advisories (CVE-2024-32760, CVE-2024-31079,
    CVE-2024-35200, CVE-2024-34161; vulnerable 1.25.0–1.25.5, 1.26.0). The image
    is built with `--with-http_v3_module`.
  - Two newer mp4 module overflows (CVE-2026-27784, CVE-2026-32647; vulnerable
    1.1.19–1.29.6). The CVE-2024-7347 patch does **not** fix these.

  None of these appear in either scanner's report (see the scanner gap above).
- **The nginx modules (`nginx-module-*`, njs 0.8.4) aren't covered by any
  scanner feed.**
- **One OpenSSL Critical/High finding remains after the bump:** CVE-2026-84782
  (no Debian fix).
