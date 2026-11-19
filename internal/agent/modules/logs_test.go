//go:build linux

package modules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// fakeJournalctl writes a script that records its arguments and prints fixture lines.
func fakeJournalctl(t *testing.T, lines ...string) (Journal, string) {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	data := filepath.Join(dir, "out.json")
	if err := os.WriteFile(data, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argsFile + "\ncat " + data + "\n"
	path := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // test helper must be executable
		t.Fatal(err)
	}
	return Journal{Path: path}, argsFile
}

func readArgs(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestJournalQuery(t *testing.T) {
	j, argsFile := fakeJournalctl(t,
		`{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","_PID":"42","MESSAGE":"GET / 200"}`,
		`{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","MESSAGE":[69,82,82,255]}`,
		`{"__CURSOR":"s=1;i=3","__REALTIME_TIMESTAMP":"1700000002000000","PRIORITY":"6","MESSAGE":"`+strings.Repeat("x", 3000)+`"}`,
	)
	prio := uint32(3)
	res, err := j.Query(context.Background(), &agentv1.LogQueryRequest{Unit: "nginx.service", MaxPriority: &prio, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(readArgs(t, argsFile), " ")
	for _, want := range []string{"--output=json", "--unit=nginx.service", "--priority=0..3", "--lines=10", "--since=-3600s"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %s in %s", want, args)
		}
	}
	if len(res.GetEntries()) != 3 || res.GetCursor() != "s=1;i=3" {
		t.Fatalf("result %v", res)
	}
	e := res.GetEntries()
	if e[0].GetPid() != 42 || e[0].GetTime().AsTime().Unix() != 1700000000 || e[1].GetMessage() != "ERR?" || len(e[2].GetMessage()) != maxLogMessage {
		t.Fatalf("entries %v", e)
	}
}

func TestJournalGrepAndCursor(t *testing.T) {
	j, argsFile := fakeJournalctl(t,
		`{"__CURSOR":"c1","MESSAGE":"connection refused"}`,
		`{"__CURSOR":"c2","MESSAGE":"all good"}`,
	)
	res, err := j.Query(context.Background(), &agentv1.LogQueryRequest{Grep: "REFUSED", AfterCursor: "c0", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetEntries()) != 1 || res.GetCursor() != "c2" {
		t.Fatalf("result %v", res)
	}
	args := strings.Join(readArgs(t, argsFile), " ")
	if !strings.Contains(args, "--after-cursor=c0") || strings.Contains(args, "--since") || !strings.Contains(args, "--lines=100") {
		t.Fatalf("args %s", args)
	}
}

func TestParseAuthEvent(t *testing.T) {
	cases := []struct {
		id, msg string
		kind    agentv1.AuthEventKind
		user    string
		ip      string
	}{
		{"sshd", "Accepted publickey for deploy from 203.0.113.5 port 52114 ssh2: ED25519 SHA256:abc", agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_ACCEPTED, "deploy", "203.0.113.5"},
		{"sshd-session", "Failed password for root from 198.51.100.7 port 4022 ssh2", agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_FAILED, "root", "198.51.100.7"},
		{"sshd", "Failed password for invalid user admin from 198.51.100.7 port 4022 ssh2", agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_INVALID_USER, "admin", "198.51.100.7"},
		{"sshd", "Invalid user oracle from 2001:db8::1 port 33", agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_INVALID_USER, "oracle", "2001:db8::1"},
		{"sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO, "alice", ""},
		{"sudo", "     bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO_FAILED, "bob", ""},
	}
	for _, c := range cases {
		ev, ok := ParseAuthEvent(c.id, c.msg)
		if !ok || ev.GetKind() != c.kind || ev.GetUser() != c.user || ev.GetSourceIp() != c.ip {
			t.Errorf("%q: %v %v", c.msg, ev, ok)
		}
	}
	if ev, _ := ParseAuthEvent("sudo", "   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id -u"); ev.GetCommand() != "/usr/bin/id -u" || ev.GetTargetUser() != "root" {
		t.Errorf("sudo fields %v", ev)
	}
	for _, msg := range []string{"Connection closed by 1.2.3.4 port 22", "pam_unix(sshd:session): session opened"} {
		if _, ok := ParseAuthEvent("sshd", msg); ok {
			t.Errorf("parsed %q", msg)
		}
	}
	if _, ok := ParseAuthEvent("cron", "Accepted publickey for x from 1.2.3.4 port 1"); ok {
		t.Error("parsed non-ssh identifier")
	}
}

func TestAuthLogQueriesIdentifiers(t *testing.T) {
	j, argsFile := fakeJournalctl(t,
		`{"__CURSOR":"a","__REALTIME_TIMESTAMP":"1700000000000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for a from 10.0.0.1 port 1 ssh2"}`,
		`{"__CURSOR":"b","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Received disconnect"}`,
	)
	res, err := j.AuthLog(context.Background(), &agentv1.AuthLogRequest{})
	if err != nil || len(res.GetEvents()) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	args := readArgs(t, argsFile)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "SYSLOG_IDENTIFIER=sudo") || !strings.Contains(joined, "--since=-86400s") {
		t.Fatalf("args %v", args)
	}
}
