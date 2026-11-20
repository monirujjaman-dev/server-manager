#!/bin/sh
# Configuration, keys and state are kept on removal so a reinstall keeps its identity;
# delete /etc/sm-agent, /etc/sm-agent-trust or /var/lib/sm-server by hand to remove them.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
