#!/bin/sh
# Create the unprivileged agent user. It joins systemd-journal to read system logs.
set -e
if ! getent group smagent >/dev/null; then
    groupadd --system smagent
fi
if ! getent passwd smagent >/dev/null; then
    useradd --system --gid smagent --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "Server Manager agent" smagent
fi
if getent group systemd-journal >/dev/null; then
    usermod -a -G systemd-journal smagent
fi
exit 0
