# syntax=docker/dockerfile:1
#
# Drop-in replacement for nginx:1.25-bookworm, built from our own nginx .deb
# (build/out/, produced by `make deb`) instead of the nginx.org package.
#
# Mirrors nginx/docker-nginx mainline/debian/Dockerfile at tag 1.25.5
# (commit 29d5001c15e7a2c7b34402c35254cc55199f8cc8): same user/group, env,
# entrypoint scripts, log symlinks, ports, stop signal and command.
#
# Deliberate differences from upstream:
#   - nginx comes from build/out/nginx_1.25.5-1~bookworm+echo1_amd64.deb
#     (source build with the CVE-2024-7347 backport)
#   - libssl3/openssl pinned to 3.0.22-1~deb12u1 (version bump)
#   - the dynamic module packages (geoip, image-filter, njs, xslt) are not installed
#
#   docker build -f Containerfile -t echo-nginx:1.25.5 .     (or: make image)

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

LABEL org.opencontainers.image.title="echo-nginx" \
      org.opencontainers.image.version="1.25.5-1~bookworm+echo1" \
      org.opencontainers.image.description="nginx 1.25.5 rebuilt from source with security fixes; drop-in for nginx:1.25-bookworm"

# Same values as upstream. NJS_* are kept so anything reading them behaves the
# same, although the njs module itself is not installed.
ENV NGINX_VERSION=1.25.5
ENV NJS_VERSION=0.8.4
ENV NJS_RELEASE=3~bookworm
ENV PKG_RELEASE=1~bookworm

ARG NGINX_DEB=nginx_1.25.5-1~bookworm+echo1_amd64.deb
ARG OPENSSL_VERSION=3.0.22-1~deb12u1

# The .deb is bind-mounted rather than COPY'd so it does not stay in a layer.
RUN --mount=type=bind,source=build/out,target=/tmp/debs \
    set -x \
# create nginx user/group first, to be consistent throughout docker variants
    && groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        "libssl3=${OPENSSL_VERSION}" \
        "openssl=${OPENSSL_VERSION}" \
        ca-certificates \
        "/tmp/debs/${NGINX_DEB}" \
        gettext-base \
        curl \
    && apt-get remove --purge --auto-remove -y && rm -rf /var/lib/apt/lists/* \
# forward request and error logs to docker log collector
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
# create a docker-entrypoint.d directory
    && mkdir /docker-entrypoint.d

COPY --chmod=755 container/docker-entrypoint.sh /
COPY --chmod=755 container/docker-entrypoint.d/10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY --chmod=755 container/docker-entrypoint.d/15-local-resolvers.envsh /docker-entrypoint.d
COPY --chmod=755 container/docker-entrypoint.d/20-envsubst-on-templates.sh /docker-entrypoint.d
COPY --chmod=755 container/docker-entrypoint.d/30-tune-worker-processes.sh /docker-entrypoint.d

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
