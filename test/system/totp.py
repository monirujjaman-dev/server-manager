#!/usr/bin/env python3
"""Helpers for the system test: create an operator interactively and compute TOTP codes.

  totp.py create-user <container> <email> <password>   prints the TOTP secret
  totp.py code <secret>                                prints the current code
"""
import base64
import hashlib
import hmac
import re
import struct
import subprocess
import sys
import time


def code(secret: str, step: int | None = None) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    if step is None:
        step = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return "%06d" % (value % 1_000_000)


def create_user(container: str, email: str, password: str) -> str:
    # `sm-server users create` asks for the password twice, prints the TOTP secret and
    # then asks for a code, so answer it as a conversation.
    proc = subprocess.Popen(
        ["docker", "exec", "-i", container, "sudo", "-u", "sm-server", "sm-server", "users", "create",
         email, "--role", "owner", "--config", "/etc/sm-server/sm-server.yaml"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    proc.stdin.write(f"{password}\n{password}\n")
    proc.stdin.flush()
    seen = ""
    while not (re.search(r"secret: [A-Z2-7]+", seen) and seen.rstrip().endswith("app:")):
        ch = proc.stderr.read(1)
        if not ch:
            break
        seen += ch
    match = re.search(r"secret: ([A-Z2-7]+)", seen)
    if not match:
        proc.kill()
        sys.exit("no TOTP secret in output:\n" + seen)
    secret = match.group(1)
    proc.stdin.write(code(secret) + "\n")
    proc.stdin.flush()
    out, err = proc.communicate(timeout=60)
    if proc.returncode != 0:
        sys.exit(f"users create failed:\n{out}\n{err}")
    return secret


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "create-user":
        print(create_user(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif len(sys.argv) == 3 and sys.argv[1] == "code":
        print(code(sys.argv[2]))
    else:
        sys.exit(__doc__)
