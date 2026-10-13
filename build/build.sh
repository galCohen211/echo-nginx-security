#!/usr/bin/env bash
# Build the nginx .deb from verified upstream source with the security patches
# from build/patches/ applied.
#
# Normally run inside build/Dockerfile (debian:bookworm-slim) via `make deb`.
# Inputs are read from $SRC_ROOT (the repository root); packages go to $OUT_DIR.
#
# Steps:
#   1. download nginx-$NGINX_VERSION.tar.gz, check pinned SHA256/SHA512 and PGP signature
#   2. check every build/patches/CVE-*.patch against SHA256SUMS (+ PGP if .asc exists)
#      and apply it with zero fuzz; any failure aborts the build
#   3. take the configure arguments verbatim from reports/upstream-nginx-V.txt
#   4. package with nginx's own Debian packaging (nginx/pkg-oss) so the file
#      layout and maintainer scripts match the upstream package
#   5. check that the built binaries report the upstream configure arguments
set -euo pipefail

SRC_ROOT=${SRC_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
OUT_DIR=${OUT_DIR:-$SRC_ROOT/build/out}
JOBS=${JOBS:-2}

NGINX_VERSION=1.25.5
NGINX_URL=https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
NGINX_SHA256=2fe2294f8af4144e7e842eaea884182a84ee7970e11046ba98194400902bbec0
# Same value as pinned by nginx's packaging repo (pkg-oss contrib/src/nginx/SHA512SUMS).
NGINX_SHA512=4a069ec08af46e42a72e263291fc84a67605d817ece1ea7092a5da5babced96ef27eb370ad6f7558b2f5973406080240080aaf4b27fc2d8b41f6853601563cb7

PKG_OSS_REF=${NGINX_VERSION}-1
PKG_OSS_URL=https://github.com/nginx/pkg-oss/archive/refs/tags/${PKG_OSS_REF}.tar.gz
PKG_OSS_SHA256=53070dffc727af6fc9ac18b56cfcf294ecdce222264e26cc9320ec96b80fc9b3

PKG_RELEASE="1~bookworm+echo1"
PKG_VENDOR=${PKG_VENDOR:-"Echo NGINX take-home <nginx-build@localhost>"}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1791849600}

# nginx.org release signing keys (https://nginx.org/en/pgp_keys.html) accepted
# for the source tarball and patches. Matched against the primary key fingerprint.
TRUSTED_FPRS=(
    43387825DDB1BB97EC36BA5D007C8D7C15D87369  # Roman Arutyunyan, build/keys/arut.key
    D6786CE303D9A9022998DC6CC8464D549AF75C0A  # Sergey Kandaurov, build/keys/pluknet.key
)

# Build in the same directory as the upstream package build, so the
# -ffile-prefix-map=<dir>=. inside the upstream --with-cc-opt applies here too.
BUILD_TOP=${BUILD_TOP:-/data/builder/debuild/nginx-${NGINX_VERSION}}
BUILD_ROOT=$BUILD_TOP/debian/debuild-base
SRCDIR=$BUILD_ROOT/nginx-${NGINX_VERSION}
DL=$BUILD_TOP/downloads

PATCH_DIR=$SRC_ROOT/build/patches
UPSTREAM_V=$SRC_ROOT/reports/upstream-nginx-V.txt

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

fetch() { curl -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"; }

verify_sig() {  # verify_sig <file> <detached-signature>
    local status fpr t
    status=$(gpg --batch --status-fd 1 --verify "$2" "$1" 2>/dev/null) \
        || die "PGP signature check failed for $(basename "$1")"
    fpr=$(awk '$2 == "VALIDSIG" { print $NF }' <<<"$status")
    for t in "${TRUSTED_FPRS[@]}"; do
        if [[ $fpr == "$t" ]]; then
            log "good PGP signature on $(basename "$1") from $fpr"
            return 0
        fi
    done
    die "$(basename "$1") is signed by untrusted key '${fpr:-none}'"
}

# --- 1. source tarball -------------------------------------------------------
export GNUPGHOME=$(mktemp -d)
gpg --batch --quiet --import "$SRC_ROOT"/build/keys/*.key

rm -rf "$BUILD_TOP"
mkdir -p "$DL" "$BUILD_ROOT"

log "downloading nginx-$NGINX_VERSION"
fetch "$NGINX_URL" "$DL/nginx.tar.gz"
fetch "$NGINX_URL.asc" "$DL/nginx.tar.gz.asc"
echo "$NGINX_SHA256  $DL/nginx.tar.gz" | sha256sum -c --quiet || die "SHA256 mismatch for nginx tarball"
echo "$NGINX_SHA512  $DL/nginx.tar.gz" | sha512sum -c --quiet || die "SHA512 mismatch for nginx tarball"
log "nginx tarball matches pinned SHA256 and SHA512"
verify_sig "$DL/nginx.tar.gz" "$DL/nginx.tar.gz.asc"

tar -C "$BUILD_ROOT" -xzf "$DL/nginx.tar.gz"

# --- 2. patches --------------------------------------------------------------
shopt -s nullglob
patches=("$PATCH_DIR"/*.patch)
shopt -u nullglob
[[ ${#patches[@]} -gt 0 ]] || die "no patches found in $PATCH_DIR"
[[ -f $PATCH_DIR/SHA256SUMS ]] || die "missing $PATCH_DIR/SHA256SUMS"

for p in "${patches[@]}"; do
    name=$(basename "$p")
    [[ $name =~ ^CVE-[0-9]{4}-[0-9]+\.patch$ ]] || die "patch '$name' is not named CVE-YYYY-NNNN.patch"
    sum=$(awk -v f="$name" '$2 == f { print $1 }' "$PATCH_DIR/SHA256SUMS")
    [[ -n $sum ]] || die "$name is not listed in SHA256SUMS"
    echo "$sum  $p" | sha256sum -c --quiet || die "SHA256 mismatch for $name"
    log "$name matches SHA256SUMS"
    if [[ -f $p.asc ]]; then
        verify_sig "$p" "$p.asc"
    fi
    log "applying $name"
    patch -d "$SRCDIR" -p1 --forward --fuzz=0 --no-backup-if-mismatch < "$p" \
        || die "$name does not apply cleanly to nginx-$NGINX_VERSION"
done

# --- 3. configure arguments --------------------------------------------------
# Strip CR in case the file was checked out with CRLF line endings: a trailing
# \r would otherwise end up inside the last argument (--with-ld-opt='... -pie').
CONFIGURE_ARGS=$(tr -d '\r' < "$UPSTREAM_V" | sed -n 's/^configure arguments: //p')
[[ -n $CONFIGURE_ARGS ]] || die "no 'configure arguments:' line in $UPSTREAM_V"
[[ $CONFIGURE_ARGS != *--with-debug* ]] || die "upstream arguments unexpectedly contain --with-debug"

# --- 4. Debian packaging (nginx/pkg-oss) -------------------------------------
log "downloading nginx/pkg-oss $PKG_OSS_REF"
fetch "$PKG_OSS_URL" "$DL/pkg-oss.tar.gz"
echo "$PKG_OSS_SHA256  $DL/pkg-oss.tar.gz" | sha256sum -c --quiet || die "SHA256 mismatch for pkg-oss"
tar -C "$DL" -xzf "$DL/pkg-oss.tar.gz"
PKG_OSS=$DL/pkg-oss-$PKG_OSS_REF

D=$SRCDIR/debian
mkdir -p "$D/source"
cp -a "$PKG_OSS/debian/debian/." "$D/"
echo "3.0 (quilt)" > "$D/source/format"
echo 11 > "$D/compat"
cp "$SRCDIR/CHANGES" "$SRCDIR/CHANGES.ru" "$D/"
cp "$PKG_OSS/docs/nginx.copyright" "$D/copyright"
printf '%s\n' "$CONFIGURE_ARGS" > "$D/configure-args"

# pkg-oss calls ./configure with its own argument list plus dpkg-buildflags.
# Replace both calls (nginx and nginx-debug) so they use the upstream argument
# string verbatim; the nginx-debug call keeps its trailing --with-debug.
sed -e 's#^\tCFLAGS="" ./configure %%BASE_CONFIGURE_ARGS%% --with-cc-opt="$(CFLAGS)" --with-ld-opt="$(LDFLAGS)"\(.*\)$#\tCFLAGS="" \&\& export CFLAGS \&\& eval "./configure $$(cat $(CURDIR)/debian/configure-args)\1"#' \
    "$D/nginx.rules.in" > "$D/rules"
chmod +x "$D/rules"
[[ $(grep -c 'debian/configure-args' "$D/rules") -eq 2 ]] || die "failed to patch both configure calls in debian/rules"
# Only these placeholders are filled by pkg-oss's Makefile; %%PROVIDES%% etc.
# are left for the rules file itself to substitute into the init scripts.
! grep -qE '%%(BASE_CONFIGURE_ARGS|CODENAME)%%' "$D/rules" || die "unreplaced template placeholder in debian/rules"

sed -e "s#%%PACKAGE_VENDOR%%#$PKG_VENDOR#g" \
    -e "s#%%BASE_VERSION%%#$NGINX_VERSION#g" \
    "$D/nginx.control.in" > "$D/control"

{
    echo "nginx ($NGINX_VERSION-$PKG_RELEASE) bookworm; urgency=medium"
    echo
    echo "  * Rebuild of nginx $NGINX_VERSION from PGP-verified upstream source."
    echo "  * Security backports:"
    for p in "${patches[@]}"; do echo "    - $(basename "$p" .patch)"; done
    echo "  * Packaging from nginx/pkg-oss $PKG_OSS_REF; configure arguments taken"
    echo "    verbatim from the upstream nginx $NGINX_VERSION-1~bookworm build."
    echo
    echo " -- $PKG_VENDOR  $(date -R -u -d "@$SOURCE_DATE_EPOCH")"
} > "$D/changelog"

log "building packages (parallel=$JOBS)"
(cd "$SRCDIR" && DEB_BUILD_OPTIONS="parallel=$JOBS" dpkg-buildpackage -b -us -uc)

# --- 5. verify ---------------------------------------------------------------
ARCH=$(dpkg --print-architecture)
DEB=$BUILD_ROOT/nginx_${NGINX_VERSION}-${PKG_RELEASE}_${ARCH}.deb
[[ -f $DEB ]] || die "expected package not found: $DEB"

X=$(mktemp -d)
dpkg-deb -x "$DEB" "$X"
for bin in nginx nginx-debug; do
    expected=$CONFIGURE_ARGS
    [[ $bin == nginx-debug ]] && expected="$CONFIGURE_ARGS --with-debug"
    got=$("$X/usr/sbin/$bin" -V 2>&1 | sed -n 's/^configure arguments: //p')
    [[ $got == "$expected" ]] || die "$bin configure arguments differ from $UPSTREAM_V"
    log "$bin -V configure arguments match upstream"
done

mkdir -p "$OUT_DIR"
cp "$BUILD_ROOT"/*.deb "$OUT_DIR/"
"$X/usr/sbin/nginx" -V > "$OUT_DIR/built-nginx-V.txt" 2>&1
(cd "$OUT_DIR" && sha256sum ./*.deb > SHA256SUMS)
log "packages written to $OUT_DIR:"
ls -l "$OUT_DIR"
