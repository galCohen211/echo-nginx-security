# Makefile (placeholder)
#
# Entry points for building, testing and scanning the hardened NGINX image.
# Targets are intentionally empty for now.

.PHONY: build image test scan clean

# Fetch and compile NGINX from source (output under build/).
build:

# Build the container image from the Containerfile.
image:

# Run the TypeScript compatibility tests in test/.
test:

# Scan the image for vulnerabilities; write results to reports/.
scan:

# Remove build output and temporary artifacts.
clean:
