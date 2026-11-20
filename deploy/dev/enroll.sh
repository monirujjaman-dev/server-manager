#!/usr/bin/env bash
# Development helper: create an enrollment token and enroll a local agent with it.
# Usage: enroll.sh <bin-dir> <server-config> <server-name> <agent-dir>
# The trust files go to <agent-dir>-trust (owned by you; a local privd needs them copied
# to a root-owned directory, see docs/DEVELOPMENT.md).
set -euo pipefail

bin="$1"
config="$2"
name="$3"
dir="$4"

out="$("$bin/sm-server" enroll create-token --config "$config" --name "$name")"
token="$(printf '%s\n' "$out" | grep -o 'smenr_[A-Za-z0-9_-]*' | head -1)"
pin="$(printf '%s\n' "$out" | grep -o -- '--pin [0-9a-f]*' | cut -d' ' -f2)"

"$bin/sm-agent" enroll --server https://127.0.0.1:8444 --pin "$pin" --token "$token" --dir "$dir" --trust-dir "$dir-trust"
