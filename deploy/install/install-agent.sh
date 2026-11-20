#!/bin/sh
# Install, enroll and start the Server Manager agent on a Linux server.
#
#   sudo SM_ENROLL_TOKEN=smenr_... sh install-agent.sh \
#       --version 0.1.0 --server https://cp.example.internal:8444 --pin <sha256>
#
# Get the token and pin from `smctl enroll create-token`. Passing the token in the
# environment keeps it out of the process list; --token also works.
#
# The package is downloaded from the GitHub release (or --base-url), and checked against
# the release's checksums.txt. If cosign is installed, the signature of checksums.txt is
# verified as well; --require-signature makes that mandatory. --package installs a local
# .deb/.rpm instead of downloading.
set -eu

REPO="monirujjaman-dev/server-manager"
version=""
server=""
pin=""
token="${SM_ENROLL_TOKEN:-}"
package=""
base_url=""
agent_url=""
require_sig=0
start=1

die() { echo "install-agent: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?}"; shift 2 ;;
        --server) server="${2:?}"; shift 2 ;;
        --pin) pin="${2:?}"; shift 2 ;;
        --token) token="${2:?}"; shift 2 ;;
        --package) package="${2:?}"; shift 2 ;;
        --base-url) base_url="${2:?}"; shift 2 ;;
        --agent-url) agent_url="${2:?}"; shift 2 ;;
        --require-signature) require_sig=1; shift ;;
        --no-start) start=0; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -d /run/systemd/system ] || die "systemd is required"
[ -n "$server" ] || die "--server is required"
[ -n "$pin" ] || die "--pin is required"
version="${version#v}"

case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac

if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    fmt=deb
elif command -v rpm >/dev/null 2>&1 && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; }; then
    fmt=rpm
else
    die "need apt (Debian/Ubuntu) or dnf/yum (RHEL/Rocky/Alma)"
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

fetch() { # url file
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
    else
        die "need curl or wget to download $1"
    fi
}

if [ -n "$package" ]; then
    [ -f "$package" ] || die "$package not found"
    pkgfile="$package"
    info "installing local package $package"
else
    [ -n "$version" ] || die "--version is required (or use --package)"
    [ -n "$base_url" ] || base_url="https://github.com/$REPO/releases/download/v$version"
    case "$base_url" in https://*) ;; *) die "--base-url must use https" ;; esac
    name="sm-agent_${version}_linux_${arch}.${fmt}"
    info "downloading $name"
    fetch "$base_url/$name" "$workdir/$name"
    fetch "$base_url/checksums.txt" "$workdir/checksums.txt"

    if command -v cosign >/dev/null 2>&1; then
        info "verifying the signature of checksums.txt"
        fetch "$base_url/checksums.txt.sigstore.json" "$workdir/checksums.txt.sigstore.json"
        cosign verify-blob --bundle "$workdir/checksums.txt.sigstore.json" \
            --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$version" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            "$workdir/checksums.txt" >/dev/null 2>&1 || die "signature verification failed"
    elif [ "$require_sig" -eq 1 ]; then
        die "--require-signature given but cosign is not installed"
    else
        echo "    note: cosign not installed; checking the SHA-256 only" >&2
    fi

    expected=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$workdir/checksums.txt")
    [ -n "$expected" ] || die "$name is not listed in checksums.txt"
    actual=$(sha256sum "$workdir/$name" | awk '{ print $1 }')
    [ "$expected" = "$actual" ] || die "checksum mismatch for $name"
    info "checksum OK"
    pkgfile="$workdir/$name"
fi

case "$fmt" in
    deb)
        # apt resolves dependencies; ./ marks a local file.
        case "$pkgfile" in /*) ;; *) pkgfile="./$pkgfile" ;; esac
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$pkgfile" >/dev/null
        ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y -q "$pkgfile" >/dev/null
        else
            yum install -y -q "$pkgfile" >/dev/null
        fi
        ;;
esac
info "installed $(sm-agent version)"

if [ -f /etc/sm-agent/agent.key ]; then
    info "already enrolled (/etc/sm-agent/agent.key exists); skipping enrollment"
else
    [ -n "$token" ] || die "no enrollment token: set SM_ENROLL_TOKEN or pass --token"
    info "enrolling with $server"
    set -- --server "$server" --pin "$pin" --dir /etc/sm-agent --owner smagent
    [ -n "$agent_url" ] && set -- "$@" --agent-url "$agent_url"
    SM_AGENT_ENROLL_TOKEN="$token" sm-agent enroll "$@"
fi

if [ "$start" -eq 1 ]; then
    systemctl enable --now sm-agent-privd.service sm-agent.service
    sleep 2
    for unit in sm-agent-privd.service sm-agent.service; do
        if ! systemctl is-active --quiet "$unit"; then
            journalctl -u "$unit" -n 20 --no-pager >&2 || true
            die "$unit did not start"
        fi
    done
    info "sm-agent is running; check it with: smctl dashboard"
fi
