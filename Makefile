# Makefile
#
# Entry points for building, testing and scanning the hardened NGINX image.
# Implemented: `deb` and `image`; the other targets are placeholders.

# Parallel compile jobs inside the build container. Kept low by default:
# Docker Desktop's VM has crashed under heavy load on this machine.
JOBS ?= 2
DEB_OUT := build/out
IMAGE ?= echo-nginx:1.25.5

.PHONY: deb build image test scan clean

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

# Run the TypeScript compatibility tests in test/.
test:

# Scan the image for vulnerabilities; write results to reports/.
scan:

# Remove build output and temporary artifacts.
clean:
