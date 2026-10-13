# Echo NGINX Security Take-Home

## Overview
This repository contains my solution to Echo's NGINX security take-home assignment.

The goal is to build a drop-in replacement for nginx:1.25-bookworm from source, remediate at least two CVEs using a version bump and a backported patch, and verify compatibility with the original image through automated HTTP tests.

The compatibility tests under test/ are written in TypeScript, as approved by Echo.

## Build Instructions

### What you need
- Docker (I used Docker Desktop on Windows)
- Make (on Windows I installed it with `winget install ezwinports.make`)
- Internet connection

### Build the nginx package
Run:

    ```powershell
    make deb
    ```

This builds nginx 1.25.5 from source inside a clean `debian:bookworm-slim`
container. The script (`build/build.sh`) does these steps:

1. Downloads the nginx source code from nginx.org and checks that it is the
   real file (checksum + PGP signature).
2. Checks each patch in `build/patches/` the same way, and applies it.
   If a patch does not apply cleanly, the build stops.
3. Builds nginx with the same options as the original image
   (taken from `reports/upstream-nginx-V.txt`).
4. Packages it as a `.deb` using nginx's official packaging files, so the
   package has the same files in the same places as the original.
5. Checks that the new nginx was built with the same options as the original.

The result is saved in `build/out/`:

- `nginx_1.25.5-1~bookworm+echo1_amd64.deb`: the nginx package
- `nginx-dbg_...deb`: debug symbols
- `built-nginx-V.txt` and `SHA256SUMS`

A full build from scratch takes about 8 minutes on my machine.
Note: Docker caches the build steps, so running `make deb` a second time
finishes in a few seconds and does not recompile.
To force a full rebuild from scratch:

```powershell
docker build --no-cache -f build/Dockerfile --build-arg JOBS=2 --target export --output type=local,dest=build/out .
```
### Build the image
Run:

```powershell
make image
```

This first builds the `.deb` (if needed), and then builds the image
`echo-nginx:1.25.5` from `Containerfile`.

The image is based on a clean `debian:bookworm-slim` and installs my
`.deb`. It is set up to match the original `nginx:1.25-bookworm` image:

- Same user setup: `nginx` user and group with ID 101
- Same port (80), entrypoint, command, stop signal and environment variables
- Same startup scripts in `/docker-entrypoint.d/` (copied from the official
  `nginxinc/docker-nginx` repo, at the commit used for 1.25.5)
- Logs go to the screen (`/dev/stdout`, `/dev/stderr`), like the original

**OpenSSL version bump:** the image installs `libssl3` and `openssl`
version `3.0.22-1~deb12u1` on purpose, instead of `3.0.11` in the original.

**Removed modules:** I did not include the geoip, image-filter, njs and
xslt modules. The default nginx config does not load them, so the default
behavior is the same. But if someone's own config loads one of these
modules with `load_module`, it will fail with this image. This is a
trade-off I chose: it removes 41 packages and many vulnerable libraries.
If these modules are needed, they can be built the same way as the main
nginx package.

To check it works:

```powershell
docker run --rm -d -p 8080:80 --name test-echo echo-nginx:1.25.5
```

Open http://localhost:8080. You should see the "Welcome to nginx!" page.

### Run the tests
Requires Node.js 20 or newer.

```powershell
make test
```

This starts the original `nginx:1.25-bookworm` and my `echo-nginx:1.25.5`
side by side, sends the same 26 requests to both (normal pages, custom
config, large files, broken requests and more), and checks that the
answers are exactly the same. It also sends a bad mp4 file that triggers
CVE-2024-7347: the original accepts it, my image rejects it.

Details in `test/README.md`.

## Image Size (original vs. new)
| Image                          | Size   |
| ------------------------------ | ------ |
| nginx:1.25-bookworm (original) | 276 MB |
| echo-nginx:1.25.5 (new)        | 140 MB |

The new image is about half the size. The main reason is that I removed
four nginx modules (geoip, image-filter, njs and xslt). The default nginx
config does not load them, so they were not used. Each module needs extra
libraries to work, and removing the modules also removed the 41 packages
they needed.

Sizes are from `docker image ls` (disk usage).
To check:

```powershell
docker image ls nginx:1.25-bookworm
docker image ls echo-nginx:1.25.5
```

## CVE Table

| ID             | Severity                          | Fix method                                | Evidence |
| -------------- | --------------------------------- | ----------------------------------------- | -------- |
| CVE-2024-7347  | Low (nginx.org)                   | Backport (official nginx patch on 1.25.5) | [Patch](build/patches/CVE-2024-7347.patch), [test](test/src/scenarios.ts): a crafted mp4 file gets `200` from the original and `500` from my image |
| CVE-2024-6119  | High (Trivy) / High (Grype)       | Version bump: OpenSSL 3.0.11 → 3.0.22     | TODO: rescan |
| CVE-2025-15467 | High (Trivy) / Critical (Grype)   | Version bump: OpenSSL 3.0.11 → 3.0.22     | TODO: rescan |

CVE-2024-7347 does not appear in the scanner reports, because the
scanners do not check nginx.org's own security list (see `TRIAGE.md`).
So its evidence comes from the patch and from the compatibility test.

## Residual Risk Assessment
**nginx still has known security problems.** nginx.org lists 24 security
issues that affect version 1.25.5. I fixed only one of them
(CVE-2024-7347). Some of the others are more serious:

- CVE-2026-42533 is rated "major". I did not fix it because nginx did
  not publish a ready patch for it.
- There are four HTTP/3 issues from 2024 (CVE-2024-32760, CVE-2024-31079,
  CVE-2024-35200, CVE-2024-34161). They matter because this nginx is
  built with HTTP/3 support.
- There are two newer bugs in the mp4 module (CVE-2026-27784,
  CVE-2026-32647). My patch does not fix them.

The scanners do not show any of these, because they don't check nginx's
own security list. I found them by reading nginx.org.

**I kept curl in the image.** People often use it to check if the
container is healthy, so removing it could break things. Removing it would
also remove 15 packages with many known vulnerabilities.

**One OpenSSL issue is still there:** CVE-2026-84782. Debian has no fix
for it yet.

**What I would do next:**
1. Upgrade to a newer nginx version (1.30 or later), if that is allowed.
   One upgrade would fix most of the problems above.
2. If we must stay on 1.25, backport more fixes, starting with HTTP/3.
3. Decide with the team if curl can be removed.
4. Check nginx.org's security list as part of every scan, because the
   scanners miss it.

## Surprises / What I'd Do Differently

## AI Usage
