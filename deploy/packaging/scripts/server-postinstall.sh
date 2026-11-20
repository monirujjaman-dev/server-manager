#!/bin/sh
set -e
install -d -m 0750 -o root -g sm-server /etc/sm-server
install -d -m 0700 -o sm-server -g sm-server /var/lib/sm-server
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    if systemctl is-active --quiet sm-server.service; then
        systemctl restart sm-server.service || true
    fi
fi
exit 0
