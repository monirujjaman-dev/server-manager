#!/bin/sh
# Stop and disable the services when the package is removed (not on upgrade).
# deb: $1 = remove|upgrade|deconfigure; rpm: $1 = 0 on removal, 1 on upgrade.
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now sm-agent.service sm-agent-privd.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
