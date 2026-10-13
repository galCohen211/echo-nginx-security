# Containerfile (placeholder)
#
# Purpose: build the hardened NGINX image.
# Planned structure:
#   - Builder stage: compile NGINX (and dependencies) from source, applying any
#     patches from build/patches/.
#   - Runtime stage: minimal base image containing only the NGINX binary, its
#     runtime libraries and config; runs as a non-root user.
#
# Not implemented yet.
