---
name: system-test
description: Build the .deb/.rpm packages and run the install/enroll/action system tests in systemd containers (Ubuntu 24.04, Rocky 9). Use after changing packaging, systemd units, the install script, enrollment or privd.
---

# Run the system tests

Requirements: Docker with a running daemon on Linux (on Windows use WSL2 with Docker
Desktop's WSL integration; on macOS Docker Desktop). Containers run systemd, so they need
`--privileged`-style cgroup access, which `test/system/run.sh` sets up.

1. `make packages` — builds into `dist/`. Check the `.deb`/`.rpm` files exist.
2. `make system-test` — or one distro: `make system-test DISTROS=ubuntu-24.04`.
   `KEEP=1` leaves the containers running for inspection (options are documented at the
   top of `test/system/run.sh`).
3. On failure, read the step that failed in the output. Inspect a container that is still
   running with `docker exec <name> journalctl -u sm-agent -u sm-agent-privd -u sm-server --no-pager`.
4. CI runs the same job ("System tests (Ubuntu 24.04, Rocky 9)"); if a distro's mirrors
   are unreachable locally, rely on CI for that distro and say so.
