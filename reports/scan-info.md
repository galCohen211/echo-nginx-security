# Baseline Scan Info

## Pinned scanner versions (reuse these exactly for the final rescan)

| Scanner | Version | Image reference (tag + digest) |
|---------|---------|--------------------------------|
| **Trivy** | **0.74.0** (released 2026-08-14) | `aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| **Grype** | **0.119.0** (released 2026-09-17, Syft v1.52.0) | `anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3` |

Versions were chosen to be recent but at least a few weeks old (newer
releases existed: Trivy 0.75.0 from 2026-10-01, Grype 0.120.x from October 2026).
The vulnerability databases are **not** pinned: they update daily, so the final
rescan will use newer DBs. Record the DB versions again at that time.

## Baseline scan

| Item | Value |
|------|-------|
| Scan date | 2026-10-13 (UTC). Grype 06:44, Trivy 07:51 |
| Target image | `nginx:1.25-bookworm` |
| Image digest | `sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c` |
| Detected OS | Debian 12.5 (bookworm) |
| Host | Windows 10, Docker Desktop (engine 29.8.2), scanners run as containers |

### Vulnerability databases used

| Scanner | DB |
|---------|----|
| Trivy | trivy-db schema v2, updated 2026-10-13 01:09:18 UTC (Java DB v1, updated 2026-10-13 01:09:47 UTC) |
| Grype | grype-db schema v6.1.10, built 2026-10-13 06:35:20 UTC |

## Commands

DB caches live in the named Docker volumes `trivy-cache` and `grype-cache`.
Run from the repository root.

```powershell
# Trivy: refresh DB, scan once to JSON, then render the table from the same JSON
docker run --rm -v trivy-cache:/root/.cache/ aquasec/trivy:0.74.0 image --download-db-only --no-progress
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ -v "${PWD}\reports:/out" `
  aquasec/trivy:0.74.0 image --no-progress --scanners vuln --format json --output /out/baseline-trivy.json nginx:1.25-bookworm
docker run --rm -v trivy-cache:/root/.cache/ -v "${PWD}\reports:/out" `
  aquasec/trivy:0.74.0 convert --format table --output /out/baseline-trivy.txt /out/baseline-trivy.json

# Grype: refresh DB, then one scan writing both formats
docker run --rm -e GRYPE_DB_CACHE_DIR=/cache -v grype-cache:/cache anchore/grype:v0.119.0 db update
docker run --rm -e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_DB_AUTO_UPDATE=false `
  -v //var/run/docker.sock:/var/run/docker.sock -v grype-cache:/cache -v "${PWD}\reports:/out" `
  anchore/grype:v0.119.0 docker:nginx:1.25-bookworm -q -o json=/out/baseline-grype.json -o table=/out/baseline-grype.txt
```

## Results (counted from the JSON reports)

A "finding" is one (package, vulnerability) pair. One CVE affecting several
packages (e.g. `openssl` and `libssl3`) counts once per package.

| Severity | Trivy findings | Trivy unique IDs | Grype findings | Grype unique IDs |
|----------|---------------:|-----------------:|---------------:|-----------------:|
| Critical | 20 | 16 | 47 | 32 |
| High | 183 | 115 | 260 | 166 |
| Medium | 327 | 206 | 267 | 166 |
| Low | 235 | 140 | 39 | 27 |
| Negligible | – | – | 135 | 84 |
| Unknown | 37 | 37 | 19 | 5 |
| **Total** | **802** | **514** | **767** | **480** |

- Overlap: 477 IDs reported by both; 37 Trivy-only (31 Debian `TEMP-*`
  placeholders, 5 DLA/DSA advisories, CVE-2023-45853 in zlib); 3 Grype-only
  (the three `nginx` findings below).
- 204 of the 477 shared IDs have a different severity in each scanner.
- Fix availability: Trivy 358 fixed / 323 affected / 100 fix_deferred / 21 will_not_fix;
  Grype 350 fixed / 241 not-fixed / 176 wont-fix.
- Critical/High with a fix available: Trivy 115 findings (88 unique IDs),
  Grype 184 findings (132 unique IDs).

### Findings against nginx packages

The image's `nginx` and `nginx-module-*` packages come from the nginx.org
repository (maintainer `NGINX Packaging <nginx-packaging@f5.com>`), not from Debian.

| Scanner | Package | ID | Severity | Installed | Fixed |
|---------|---------|----|----------|-----------|-------|
| Grype | nginx | CVE-2023-44487 | High | 1.25.5-1~bookworm | – (not-fixed) |
| Grype | nginx | CVE-2013-0337 | Low | 1.25.5-1~bookworm | – (wont-fix) |
| Grype | nginx | CVE-2009-4487 | Negligible | 1.25.5-1~bookworm | – (not-fixed) |
| Trivy 0.74.0 | – | none | – | – | – |

- Grype matched by package name against Debian's nginx entries with no version
  constraint (`versionConstraint: none (unknown)`).
- Trivy 0.58.1 reported the same three CVEs (all LOW); Trivy 0.74.0 reports none.
  Checked by re-running 0.58.1 against the same DB.
- No findings from either scanner for `nginx-module-geoip`, `-image-filter`,
  `-njs` (1.25.5+0.8.4) or `-xslt`.

## Notes on the run

- A cold Trivy cache means downloading ~127 MB (vuln DB) + ~937 MB (Java DB);
  with Trivy's default 5-minute timeout the first-ever 0.58.1 run failed. Refreshing
  the DB as a separate step (above) avoids this.
- Grype 0.92.2 (first attempt) could not import the current v6 DB
  (`UNIQUE constraint failed: operating_systems...`), hence 0.119.0.
- The first Grype attempt also coincided with a Docker Desktop WSL VM crash;
  downloading the Grype DB as a separate step keeps the scan lighter.
- Superseded: an earlier baseline used Trivy 0.58.1 (802 vs. 805 findings; the
  difference is the three nginx CVEs).

## Rescan of echo-nginx:1.25.5

Run with `make scan` (`tools/scan.mjs`): same pinned images and flags as above. Scanner and DB versions are
recorded in `echo-scan-info.md`. On 2026-10-13 both DBs were **identical** to the baseline (trivy-db updated
2026-10-13 01:09:18 UTC, grype-db v6.1.10 built 2026-10-13 06:35:20 UTC), so `diff.md` reflects image changes only.
