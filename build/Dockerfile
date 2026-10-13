# syntax=docker/dockerfile:1
#
# Package build environment for nginx (see build/build.sh).
# Compiles nginx from verified upstream source; no pre-built nginx binaries
# are used. The only output is the .deb packages, exported via:
#
#   docker build -f build/Dockerfile --target export --output type=local,dest=build/out .
#
# (`make deb` runs exactly this.) The build context is the repository root;
# .dockerignore limits it to the files build.sh needs.

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS builder

# Build-Depends of nginx's pkg-oss packaging, plus download/verification tools.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        debhelper \
        dpkg-dev \
        gnupg \
        libpcre2-dev \
        libssl-dev \
        lsb-release \
        patch \
        quilt \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

ARG JOBS=2

WORKDIR /src
COPY reports/upstream-nginx-V.txt reports/
COPY build/keys/ build/keys/
COPY build/patches/ build/patches/
COPY build/build.sh build/

RUN SRC_ROOT=/src OUT_DIR=/out JOBS=${JOBS} bash build/build.sh

FROM scratch AS export
COPY --from=builder /out/ /
