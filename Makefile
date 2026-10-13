# Makefile
#
# Entry points for building, testing and scanning the hardened NGINX image.
# Implemented: `deb`, `image`, `test`, `scan`, `vex`; the other targets are placeholders.

# Parallel compile jobs inside the build container. Kept low by default:
# Docker Desktop's VM has crashed under heavy load on this machine.
JOBS ?= 2
DEB_OUT := build/out
IMAGE ?= echo-nginx:1.25.5

.PHONY: deb build image test scan vex clean

# Build the nginx .deb from source (build/Dockerfile + build/build.sh).
# Output: build/out/*.deb, built-nginx-V.txt, SHA256SUMS.
deb:
	docker build -f build/Dockerfile --build-arg JOBS=$(JOBS) \
		--target export --output type=local,dest=$(DEB_OUT) .

# Fetch and compile NGINX from source (output under build/).
build:

# Build the container image from the Containerfile, using the .deb from `deb`.
image: deb
	docker build -f Containerfile -t $(IMAGE) .

# Compatibility test (test/): echo-nginx vs nginx:1.25-bookworm. Needs Node.js 20+.
# The recipe must work under both cmd.exe (Windows make) and sh, so all logic
# (Node version check, image pull, npm ci, build, run) is in test/scripts/run.cjs.
# Only "is node on PATH at all" is checked here, since run.cjs needs node to start.
UPSTREAM_IMAGE ?= nginx:1.25-bookworm
NODE_VERSION = $(shell node --version 2>&1)

test: image
	$(if $(filter v%,$(NODE_VERSION)),,$(error Node.js 20+ is required for 'make test' but node was not found in PATH))
	node test/scripts/run.cjs --upstream $(UPSTREAM_IMAGE) --candidate $(IMAGE)

# Scan the image with the pinned Trivy/Grype versions (reports/echo-*), record
# the DB versions (reports/echo-scan-info.md) and compare with the baseline
# (reports/diff.md). Logic is in tools/scan.mjs so it works under cmd.exe and sh.
scan: image
	$(if $(filter v%,$(NODE_VERSION)),,$(error Node.js 20+ is required for 'make scan' but node was not found in PATH))
	node tools/scan.mjs --image $(IMAGE)

# Generate the CVE-2024-7347 VEX for the image digest currently built (from
# vex/CVE-2024-7347.openvex.template.json) and show it suppresses the CVE on that
# image only: binary SBOM + Grype without/with --vex, for our image and upstream.
# Output: reports/vex/ (incl. the generated VEX), reports/vex-demo.md. Logic is in tools/vex.mjs.
vex: image
	$(if $(filter v%,$(NODE_VERSION)),,$(error Node.js 20+ is required for 'make vex' but node was not found in PATH))
	node tools/vex.mjs --image $(IMAGE) --upstream $(UPSTREAM_IMAGE)

# Remove build output and temporary artifacts.
clean:
