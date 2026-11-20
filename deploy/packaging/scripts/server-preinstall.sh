#!/bin/sh
set -e
if ! getent group sm-server >/dev/null; then
    groupadd --system sm-server
fi
if ! getent passwd sm-server >/dev/null; then
    useradd --system --gid sm-server --no-create-home --home-dir /var/lib/sm-server \
        --shell /usr/sbin/nologin --comment "Server Manager control plane" sm-server
fi
exit 0
