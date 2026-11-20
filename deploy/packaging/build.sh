#!/usr/bin/env bash
# Build release artefacts into <dist>:
#   sm-agent / sm-server / smctl  .deb and .rpm for linux amd64 and arm64
#   smctl binaries for macOS and Windows
#   install-agent.sh
#   checksums.txt (SHA-256 of everything above)
# Usage: build.sh <dist-dir> <package-version> <go-ldflags>
set -euo pipefail

dist="$1"
version="$2"
ldflags="$3"
tool=(go tool -modfile=tools/go.mod)

case "$dist" in
    ""|/|.|..) echo "refusing to use '$dist' as the output directory" >&2; exit 1 ;;
esac
rm -rf -- "$dist"
mkdir -p "$dist"

for arch in amd64 arm64; do
    bin="$dist/.build/linux-$arch"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$bin/" ./cmd/...
    for pkg in agent server smctl; do
        name="sm-$pkg"
        [ "$pkg" = smctl ] && name=smctl
        # nfpm expands ${ARCH} and ${VERSION} itself but not paths in "contents".
        cfg="$dist/.build/nfpm-$pkg-$arch.yaml"
        sed "s|\${BIN_DIR}|$bin|g" "deploy/packaging/nfpm-$pkg.yaml" > "$cfg"
        for fmt in deb rpm; do
            ARCH="$arch" VERSION="$version" "${tool[@]}" nfpm package \
                --config "$cfg" --packager "$fmt" \
                --target "$dist/${name}_${version}_linux_${arch}.${fmt}" >/dev/null
        done
    done
done

# Operators' workstations.
for target in darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
    os="${target%/*}"
    arch="${target#*/}"
    ext=""
    [ "$os" = windows ] && ext=".exe"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" \
        -o "$dist/smctl_${version}_${os}_${arch}${ext}" ./cmd/smctl
done

cp deploy/install/install-agent.sh "$dist/"

rm -rf -- "$dist/.build"
(cd "$dist" && sha256sum -- * > checksums.txt)
ls -l "$dist"
