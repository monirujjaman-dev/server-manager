#!/bin/sh
# The agent starts after enrollment (its unit requires /etc/sm-agent/agent.yaml). On an
# upgrade, restart running services so the new binary is used.
set -e
install -d -m 0700 -o smagent -g smagent /etc/sm-agent
# Root-owned trust anchors for the privileged helper (command key, server identity). The
# agent can read them but never write them; see `sm-agent migrate-trust --help`.
install -d -m 0755 -o root -g root /etc/sm-agent-trust
# Swap state written by the privileged helper; /etc/sysctl.d/90-sm-swappiness.conf links
# to swappiness.conf, which starts empty so the link is never dangling.
install -d -m 0755 -o root -g root /var/lib/smswap
if [ ! -e /var/lib/smswap/swappiness.conf ]; then
    install -m 0644 -o root -g root /dev/null /var/lib/smswap/swappiness.conf
fi
# Upgrades from versions that kept the command key in /etc/sm-agent copy it once. The
# agent controls the files this reads, so it is attempted at most once per host: the
# marker is written first, by every install (fresh ones included), and a failed or
# skipped migration is never retried on a later upgrade. Re-enroll in that case.
if [ ! -e /etc/sm-agent-trust/.migration-done ]; then
    install -m 0644 -o root -g root /dev/null /etc/sm-agent-trust/.migration-done
    if [ -f /etc/sm-agent/agent.crt ] && [ ! -e /etc/sm-agent-trust/command.pub ] && [ ! -e /etc/sm-agent-trust/server-id ]; then
        /usr/bin/sm-agent migrate-trust || echo "sm-agent: migrate-trust failed; re-enroll this server" >&2
    fi
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    for unit in sm-agent-privd.service sm-agent.service; do
        if systemctl is-active --quiet "$unit"; then
            systemctl restart "$unit" || true
        fi
    done
fi
exit 0
