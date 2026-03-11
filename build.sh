#!/usr/bin/env bash
# build.sh — cross-compile p2pvpn for all supported platforms.
# Outputs are placed in dist/ with the naming convention:
#   p2pvpn-<os>-<arch>[.exe]

set -euo pipefail

BINARY="p2pvpn"
DIST="dist"
LDFLAGS="-s -w"

mkdir -p "$DIST"

build() {
    local goos="$1"
    local goarch="$2"
    local label="$3"
    local extra="${4:-}"

    local out="$DIST/${BINARY}-${label}"
    [[ "$goos" == "windows" ]] && out="${out}.exe"

    echo "Building ${label}..."
    env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" $extra \
        go build -ldflags="$LDFLAGS" -o "$out" .
    chmod +x "$out"
}

# ─── Linux ───────────────────────────────────────────────────────────────────
build linux amd64   linux-x64
build linux 386     linux-x86
build linux arm     linux-arm   "GOARM=7"
build linux arm64   linux-arm64

# ─── Windows ─────────────────────────────────────────────────────────────────
build windows amd64 windows-x64
build windows arm64 windows-arm64

# windows/arm is supported by Go but excluded here: winipcfg syscall stubs
# for windows/arm are incomplete in golang.org/x/sys as of this writing.

echo ""
echo "Done. Binaries in ./$DIST/:"
ls -lh "$DIST/"
