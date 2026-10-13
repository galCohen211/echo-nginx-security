# VEX demonstration: CVE-2024-7347

Written by `tools/vex.mjs` (`make vex`).

VEX document: `vex/CVE-2024-7347.openvex.json` in this directory, generated from `vex/CVE-2024-7347.openvex.template.json`
for `echo-nginx:1.25.5` with digest `sha256:1708c089be4ac99953dc3e81d861babfed8cce166d2cacd4383c711a01bb0516` (different from the committed example `vex/CVE-2024-7347.openvex.json` (`pkg:oci/echo-nginx@sha256%3A39b97e573139adce9c1846d5dedfa72d50b94da43ec01b9cfff265a4ac7cd134`, the author's build); expected after a rebuild).
Tools: `anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02`, `anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3`.

Each image is described by a Syft SBOM restricted to the binary cataloger, which identifies
`/usr/sbin/nginx` as `pkg:generic/nginx@1.25.5` (CPE `cpe:2.3:a:f5:nginx:1.25.5`). Grype then matches
it against the upstream nginx CVEs. Why binary-only: see `vex/README.md`.

| Image | `--vex` | Matches (all binaries) | nginx CVEs | CVE-2024-7347 | Ignored by VEX | Output |
|---|---|---:|---:|---|---|---|
| echo (`echo-nginx:1.25.5`) | no | 89 | 21 | **reported** (pkg:generic/nginx@1.25.5) | – | `vex/echo-grype.json` |
| echo (`echo-nginx:1.25.5`) | yes | 88 | 20 | not reported | pkg:generic/nginx@1.25.5 (vex: fixed) | `vex/echo-grype-vex.json` |
| upstream (`nginx:1.25-bookworm`) | no | 131 | 21 | **reported** (pkg:generic/nginx@1.25.5) | – | `vex/upstream-grype.json` |
| upstream (`nginx:1.25-bookworm`) | yes | 131 | 21 | **reported** (pkg:generic/nginx@1.25.5) | – | `vex/upstream-grype-vex.json` |

Both images contain a binary with the same identifier `pkg:generic/nginx@1.25.5`; the statement
applies to ours only because the VEX product is our image digest.

## Checks

- PASS: echo without --vex reports CVE-2024-7347
- PASS: echo with --vex does not report CVE-2024-7347
- PASS: echo with --vex lists CVE-2024-7347 as ignored by VEX
- PASS: upstream without --vex reports CVE-2024-7347
- PASS: upstream with --vex still reports CVE-2024-7347 (statement is scoped to our digest)
