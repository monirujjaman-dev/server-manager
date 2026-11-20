#!/usr/bin/env bash
# System test: install the real packages in systemd containers and drive them with smctl.
#
#   sm-db     PostgreSQL
#   sm-cp     Ubuntu 24.04 + sm-server and smctl packages, started by systemd
#   sm-<os>   one agent per distribution, installed with deploy/install/install-agent.sh
#
# Checks run against real systemd, D-Bus and journald: service restart/stop/start, process
# signals, journal queries, sudo records, metrics, unit hardening, revocation and package
# removal.
#
# Environment: DIST (default dist), PKG_VERSION (required), DISTROS (default
# "ubuntu-24.04 rocky-9"), KEEP=1 to leave the containers running afterwards.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
dist="${DIST:-dist}"
case "$dist" in /*) ;; *) dist="$root/$dist" ;; esac
version="${PKG_VERSION:?set PKG_VERSION}"
distros="${DISTROS:-ubuntu-24.04 rocky-9}"
net=sm-systest
password="system test password"
email=owner@example.com
failures=0

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }
check() { # description, command...
    local desc="$1"; shift
    if out="$("$@" 2>&1)"; then pass "$desc"; else fail "$desc"; printf '%s\n' "$out" | sed 's/^/       /' | tail -15; fi
}
cp_exec() { docker exec sm-cp "$@"; }
smctl() { docker exec sm-cp smctl "$@"; }
retry() { # seconds, command...
    local until=$((SECONDS + $1)); shift
    until "$@" >/dev/null 2>&1; do
        [ $SECONDS -lt $until ] || return 1
        sleep 2
    done
}

cleanup() {
    local status=$?
    if [ "$status" -ne 0 ] || [ "$failures" -gt 0 ]; then
        for c in sm-cp $(for d in $distros; do echo "sm-$d"; done); do
            echo "--- journal of $c"
            docker exec "$c" journalctl -u 'sm-*' --no-pager -n 100 2>/dev/null || true
        done
    fi
    if [ "${KEEP:-0}" = 1 ]; then
        echo "KEEP=1: containers left running (docker ps --filter network=$net)"
        return
    fi
    local names=(sm-db sm-cp)
    for d in $distros; do names+=("sm-$d"); done
    docker rm -f "${names[@]}" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# systemd as PID 1 needs a writable cgroup tree: on cgroup v2 hosts a private cgroup
# namespace, on v1 hosts the host's hierarchy mounted read-write.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    cgroup_args=(--cgroupns=private)
else
    cgroup_args=(--cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw)
fi

start_systemd() { # name image
    docker run -d --name "$1" --hostname "$1" --network "$net" \
        --privileged "${cgroup_args[@]}" \
        --tmpfs /run --tmpfs /run/lock "$2" >/dev/null
    # shellcheck disable=SC2016 # expanded inside the container
    retry 60 docker exec "$1" sh -c 'state=$(systemctl is-system-running 2>/dev/null); [ "$state" = running ] || [ "$state" = degraded ]' \
        || { echo "systemd did not start in $1"; docker logs "$1" | tail -20; return 1; }
}

log "building systemd images"
for d in $distros; do
    docker build -q -t "sm-test-$d" -f "$here/images/$d.Dockerfile" "$here/images" >/dev/null
done
# The control plane always runs on Ubuntu.
docker build -q -t sm-test-ubuntu-24.04 -f "$here/images/ubuntu-24.04.Dockerfile" "$here/images" >/dev/null

cleanup
docker network create "$net" >/dev/null

log "starting PostgreSQL and the control plane"
docker run -d --name sm-db --hostname sm-db --network "$net" \
    -e POSTGRES_USER=sm -e POSTGRES_PASSWORD=sm-systest -e POSTGRES_DB=sm postgres:17.11-alpine >/dev/null
start_systemd sm-cp sm-test-ubuntu-24.04
docker cp "$dist/sm-server_${version}_linux_amd64.deb" sm-cp:/tmp/sm-server.deb
docker cp "$dist/smctl_${version}_linux_amd64.deb" sm-cp:/tmp/smctl.deb
cp_exec sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/sm-server.deb /tmp/smctl.deb >/dev/null'
check "sm-server package installed with its user" cp_exec id sm-server
cp_exec sh -c 'sed -e "s|^database_url:.*|database_url: postgres://sm:sm-systest@sm-db:5432/sm?sslmode=disable|" \
    -e "s|cp.example.internal|sm-cp|g" -e "s|format: json|format: text|" \
    /etc/sm-server/sm-server.yaml.example > /etc/sm-server/sm-server.yaml && \
    echo "heartbeat_interval: 2s" >> /etc/sm-server/sm-server.yaml && \
    chgrp sm-server /etc/sm-server/sm-server.yaml && chmod 0640 /etc/sm-server/sm-server.yaml'
retry 60 docker exec sm-db pg_isready -U sm -d sm
cp_exec sudo -u sm-server sm-server migrate up --config /etc/sm-server/sm-server.yaml
cp_exec sudo -u sm-server sm-server pki init --dns sm-cp --config /etc/sm-server/sm-server.yaml >/dev/null
cp_exec systemctl enable --now sm-server.service
ca=/var/lib/sm-server/pki/root.crt
check "control plane serving under systemd" retry 60 docker exec sm-cp smctl health --server https://sm-cp:8444 --ca-file "$ca"

log "creating an operator and logging in"
secret="$(python3 "$here/totp.py" create-user sm-cp "$email" "$password")"
printf '%s\n%s\n' "$password" "$(python3 "$here/totp.py" code "$secret")" |
    docker exec -i sm-cp smctl login --server https://sm-cp:8444 --ca-file "$ca" --email "$email" >/dev/null
check "smctl whoami shows the owner role" sh -c 'docker exec sm-cp smctl whoami | grep -q "owner on all servers"'

for d in $distros; do
    name="sm-$d"
    log "agent on $d"
    case "$d" in ubuntu*|debian*) fmt=deb ;; *) fmt=rpm ;; esac
    start_systemd "$name" "sm-test-$d"
    docker cp "$dist/sm-agent_${version}_linux_amd64.$fmt" "$name:/tmp/sm-agent.$fmt"
    docker cp "$root/deploy/install/install-agent.sh" "$name:/tmp/install-agent.sh"

    out="$(smctl enroll create-token --name "$d")"
    token="$(printf '%s\n' "$out" | grep -o 'smenr_[A-Za-z0-9_-]*' | head -1)"
    pin="$(printf '%s\n' "$out" | grep -o -- '--pin [0-9a-f]*' | head -1 | cut -d' ' -f2)"
    check "install script installs, enrolls and starts the agent" \
        docker exec -e SM_ENROLL_TOKEN="$token" "$name" sh /tmp/install-agent.sh \
            --package "/tmp/sm-agent.$fmt" --server https://sm-cp:8444 --pin "$pin"

    # A unit to control, and a log line to find.
    docker exec "$name" sh -c 'printf "[Service]\nExecStart=/bin/sh -c \"echo sm-test started; exec sleep infinity\"\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/sm-test.service && systemctl daemon-reload && systemctl enable --now sm-test.service'

    check "agent runs as smagent, helper as root" sh -c "
        [ \"\$(docker exec $name ps -o user= -C sm-agent | sort | tr '\n' ' ')\" = 'root smagent ' ]"
    check "helper socket is root:smagent 0660" sh -c "
        [ \"\$(docker exec $name stat -c '%U:%G %a' /run/sm-agent/privd.sock)\" = 'root:smagent 660' ]"
    check "agent key belongs to smagent, mode 0600" sh -c "
        [ \"\$(docker exec $name stat -c '%U %a' /etc/sm-agent/agent.key)\" = 'smagent 600' ]"
    check "server online in the dashboard" retry 60 sh -c "docker exec sm-cp smctl servers list | grep -E '^$d +' | grep -q online"
    check "metrics reported" retry 60 sh -c "docker exec sm-cp smctl dashboard | grep -E '^$d' | grep -q ' ago'"
    check "system info" sh -c "docker exec sm-cp smctl system info $d | grep -q '^host *$name'"
    check "services list sees the test unit" sh -c "docker exec sm-cp smctl services list $d --filter sm-test | grep -q 'sm-test.service *active'"

    before="$(docker exec "$name" systemctl show -p InvocationID --value sm-test.service)"
    check "restart a service through the helper" smctl services restart "$d" sm-test
    after="$(docker exec "$name" systemctl show -p InvocationID --value sm-test.service)"
    if [ -n "$after" ] && [ "$before" != "$after" ]; then pass "systemd really restarted the unit"; else fail "unit was not restarted ($before -> $after)"; fi
    check "stop refused without --yes" sh -c "! docker exec sm-cp smctl services stop $d sm-test"
    check "stop with --yes" smctl services stop "$d" sm-test --yes
    check "unit is inactive after stop" sh -c "[ \"\$(docker exec $name systemctl is-active sm-test.service)\" = inactive ]"
    check "start again" smctl services start "$d" sm-test

    check "journal query finds the unit's output" retry 20 sh -c "docker exec sm-cp smctl logs $d --unit sm-test --since 10m | grep -q 'sm-test started'"
    # A record in sudo's exact format, written to journald under the sudo identifier.
    # (Running sudo itself depends on each image's PAM setup, e.g. SSSD on Rocky.)
    check "write a sudo record to the journal" docker exec "$name" logger -t sudo \
        "    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/systemctl status sm-test"
    check "sudo use shows up in logins" retry 20 sh -c "docker exec sm-cp smctl logins $d --since 10m | grep -q 'sudo .*systemctl status sm-test'"

    pid="$(docker exec "$name" sh -c 'nohup sleep 600 >/dev/null 2>&1 & echo $!')"
    start="$(docker exec "$name" awk '{print $22}' "/proc/$pid/stat")"
    check "kill a process by PID and start time" smctl processes kill "$d" "$pid" --start "$start" --yes
    check "the process is gone" retry 10 sh -c "! docker exec $name kill -0 $pid"
    check "PID 1 is refused" sh -c "! docker exec sm-cp smctl processes kill $d 1 --yes"

    exposure="$(docker exec "$name" systemd-analyze security sm-agent.service --no-pager 2>/dev/null | tail -1 || true)"
    echo "  sm-agent.service: ${exposure:-systemd-analyze unavailable}"
    exposure="$(docker exec "$name" systemd-analyze security sm-agent-privd.service --no-pager 2>/dev/null | tail -1 || true)"
    echo "  sm-agent-privd.service: ${exposure:-systemd-analyze unavailable}"

    check "revoke the server" smctl servers revoke "$d" --reason "system test" --yes
    check "agent disconnected after revoke" retry 30 sh -c "docker exec sm-cp smctl servers list | grep -E '^$d +' | grep -q revoked"

    case "$fmt" in
        deb) docker exec "$name" sh -c 'DEBIAN_FRONTEND=noninteractive apt-get remove -y -q sm-agent >/dev/null' ;;
        rpm) docker exec "$name" dnf remove -y -q sm-agent >/dev/null ;;
    esac
    check "removing the package stops the services" sh -c "! docker exec $name systemctl is-active --quiet sm-agent-privd.service"
    check "removing the package keeps the identity" docker exec "$name" test -f /etc/sm-agent/agent.key
done

log "audit chain"
check "audit chain verifies" cp_exec sudo -u sm-server sm-server audit verify --config /etc/sm-server/sm-server.yaml

echo
if [ "$failures" -gt 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all system checks passed"
