#!/bin/sh
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now sm-server.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
