# Installation

Packages are published on the project's GitHub releases for `linux/amd64` and
`linux/arm64`:

| Package | Contains |
|---------|----------|
| `sm-server_<version>_linux_<arch>.deb` / `.rpm` | control plane, systemd unit, example config |
| `sm-agent_<version>_linux_<arch>.deb` / `.rpm` | agent and privileged helper, two systemd units |
| `smctl_<version>_linux_<arch>.deb` / `.rpm` | operator console (also as plain binaries for macOS and Windows) |
| `install-agent.sh` | installs, enrolls and starts an agent in one command |
| `checksums.txt`, `checksums.txt.sigstore.json` | SHA-256 of every file, signed by the release workflow |

Supported: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9 and derivatives (Rocky, Alma). The
system tests run on Ubuntu 24.04 and Rocky 9.

## Verify a download

```bash
sha256sum --ignore-missing -c checksums.txt
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/monirujjaman-dev/server-manager/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

## Where things run

- **Control plane:** a small, always-on Linux VM in a cloud (2 vCPU / 4 GB is enough for
  about 200 servers), or one of your managed servers. Not your laptop: agents must reach it
  at any time, and jobs queue there while you are offline.
- **`smctl`:** your workstation (Windows, macOS or Linux). Download the binary for your
  platform from the release, or install the `smctl` package on Linux.
- **Agents:** every managed Linux server.

Firewall for the control-plane VM:

| Port | From | Why |
|------|------|-----|
| 8443/tcp (agent gateway) | your servers, or the internet | mTLS only; unknown or revoked certificates are refused (ADR 0009) |
| 8444/tcp (operator API + enrollment) | your VPN, your IP addresses, and new servers while they enroll | keep it off the open internet |

## 1. Control plane

```bash
sudo apt install ./sm-server_<version>_linux_amd64.deb      # or: sudo dnf install ./sm-server_….rpm
```

Create a PostgreSQL 16+ database and a role for it, then configure:

```bash
sudo cp /etc/sm-server/sm-server.yaml.example /etc/sm-server/sm-server.yaml
sudo chgrp sm-server /etc/sm-server/sm-server.yaml && sudo chmod 0640 /etc/sm-server/sm-server.yaml
sudoedit /etc/sm-server/sm-server.yaml      # database_url, public_agent_url, public_api_url
```

Initialise the schema and the internal CA as the `sm-server` user, so the files belong
to it, then start the service:

```bash
sudo -u sm-server sm-server migrate up --config /etc/sm-server/sm-server.yaml
sudo -u sm-server sm-server pki init --dns cp.example.internal --config /etc/sm-server/sm-server.yaml
sudo systemctl enable --now sm-server
```

`pki init` prints the server key pin. Move `/var/lib/sm-server/pki/root.key` to offline
storage afterwards; it is only needed to issue a new intermediate CA.

Create the first operator. It asks for a password, shows a TOTP secret for an
authenticator app, and requires one valid code before saving:

```bash
sudo -u sm-server sm-server users create you@example.com --role owner --config /etc/sm-server/sm-server.yaml
```

Back up the PostgreSQL database and `/var/lib/sm-server/pki` (CA, command-signing key and
`secrets.key`, which encrypts the TOTP secrets).

## 2. Operator console (your workstation)

Copy `/var/lib/sm-server/pki/root.crt` from the control plane to your workstation (for
example with `scp`), then:

```bash
smctl login --server https://cp.example.internal:8444 --ca-file root.crt
smctl whoami
```

On Windows, run `smctl.exe` in Windows Terminal, PowerShell or cmd. In Git Bash (mintty)
the password prompt cannot hide input; use `winpty smctl login` there. The session is
stored in `%AppData%\smctl\session.json` (Windows), `~/Library/Application
Support/smctl/session.json` (macOS) or `~/.config/smctl/session.json` (Linux), readable only
by you.

## 3. Agents

Create a one-time token for each server (admin role; `smctl` asks for a fresh MFA code):

```bash
smctl enroll create-token --name web-1 --group production
```

It prints the commands for the new server. With the install script:

```bash
curl -fsSLO https://github.com/monirujjaman-dev/server-manager/releases/download/v<version>/install-agent.sh
sudo SM_ENROLL_TOKEN=smenr_… sh install-agent.sh --version <version> \
  --server https://cp.example.internal:8444 --pin <pin>
```

The script detects apt or dnf and the CPU architecture, downloads the package, checks it
against `checksums.txt` (and the signature, if `cosign` is installed; add
`--require-signature` to insist), installs it, enrolls with the token and starts
`sm-agent-privd` and `sm-agent`. Use `--package ./sm-agent_….deb` to install a file you
copied yourself, and `--base-url` to download from a mirror.

The packages create:

- user `smagent` (no login, member of `systemd-journal`), which runs `sm-agent`
- `/etc/sm-agent` (mode 0700, owned by `smagent`) for the key, certificates and config
- `sm-agent-privd.service` (root, no network) and `sm-agent.service`, which starts only
  after enrollment

## Upgrades and removal

Install the newer package the same way; running services are restarted. Removing a
package stops and disables its services but keeps `/etc/sm-agent` or
`/var/lib/sm-server`, so a reinstall keeps the server's identity. Delete those
directories to remove the identity, and revoke the server with
`smctl servers revoke <name>`.
