#!/bin/sh
# The agent starts after enrollment (its unit requires /etc/sm-agent/agent.yaml). On an
# upgrade, restart running services so the new binary is used.
set -e
install -d -m 0700 -o smagent -g smagent /etc/sm-agent
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    for unit in sm-agent-privd.service sm-agent.service; do
        if systemctl is-active --quiet "$unit"; then
            systemctl restart "$unit" || true
        fi
    done
fi
exit 0
