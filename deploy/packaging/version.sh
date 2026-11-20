#!/bin/sh
# Print the package version: X.Y.Z for a commit tagged vX.Y.Z, else 0.0.0-dev.<commit>
# (deb versions must start with a digit).
tag=$(git describe --tags --exact-match 2>/dev/null || true)
case "$tag" in
    v[0-9]*) echo "${tag#v}" ;;
    *) echo "0.0.0-dev.$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" ;;
esac
