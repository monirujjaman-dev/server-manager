package modules

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

const (
	maxLogMessage = 1024
	maxLogLines   = 500
	// grepScanFactor: with a grep filter, this many times more entries are read so that
	// enough matches remain after filtering.
	grepScanFactor = 20
)

// Journal reads systemd-journald through journalctl. Arguments are passed as an
// argument vector (never through a shell) and every value is attached to its flag with
// "=", so no parameter can be read as an extra option.
type Journal struct {
	// Path to journalctl; "journalctl" uses $PATH.
	Path string
}

type journalEntry struct {
	Cursor     string          `json:"__CURSOR"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
	Priority   string          `json:"PRIORITY"`
	Unit       string          `json:"_SYSTEMD_UNIT"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	PID        string          `json:"_PID"`
	Message    json.RawMessage `json:"MESSAGE"`
}

func (j Journal) run(ctx context.Context, args []string) ([]journalEntry, error) {
	path := j.Path
	if path == "" {
		path = "journalctl"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, append([]string{"--output=json", "--no-pager", "--quiet"}, args...)...) //nolint:gosec // fixed binary, validated arguments
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("journalctl: %w: %s", err, msg)
	}
	var out []journalEntry
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		var e journalEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// message decodes MESSAGE, which journald exports as a string, or as a byte array when
// it is not valid UTF-8.
func (e journalEntry) message() string {
	var s string
	if json.Unmarshal(e.Message, &s) == nil {
		return s
	}
	var b []byte
	var nums []int
	if json.Unmarshal(e.Message, &nums) == nil {
		for _, n := range nums {
			b = append(b, byte(n)) //nolint:gosec // journald byte values
		}
		return strings.ToValidUTF8(string(b), "?")
	}
	return ""
}

func (e journalEntry) time() *timestamppb.Timestamp {
	us, err := strconv.ParseInt(e.Realtime, 10, 64)
	if err != nil {
		return nil
	}
	return timestamppb.New(time.UnixMicro(us))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// Query returns journal entries, oldest first, plus the cursor of the last one.
func (j Journal) Query(ctx context.Context, req *agentv1.LogQueryRequest) (*agentv1.LogQueryResult, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, maxLogLines)
	fetch := limit
	if req.GetGrep() != "" {
		fetch = limit * grepScanFactor
	}
	args := []string{"--lines=" + strconv.Itoa(fetch)}
	if req.GetAfterCursor() != "" {
		args = append(args, "--after-cursor="+req.GetAfterCursor())
	} else {
		since := req.GetSinceSeconds()
		if since == 0 {
			since = 3600
		}
		args = append(args, "--since=-"+strconv.FormatUint(uint64(since), 10)+"s")
	}
	if req.GetUnit() != "" {
		args = append(args, "--unit="+req.GetUnit())
	}
	if req.MaxPriority != nil {
		args = append(args, "--priority=0.."+strconv.FormatUint(uint64(req.GetMaxPriority()), 10))
	}
	entries, err := j.run(ctx, args)
	if err != nil {
		return nil, err
	}
	grep := strings.ToLower(req.GetGrep())
	res := &agentv1.LogQueryResult{Cursor: req.GetAfterCursor()}
	for _, e := range entries {
		res.Cursor = e.Cursor // advance even past non-matching entries
		msg := e.message()
		if grep != "" && !strings.Contains(strings.ToLower(msg), grep) {
			continue
		}
		prio, _ := strconv.ParseUint(e.Priority, 10, 32)
		pid, _ := strconv.ParseInt(e.PID, 10, 32)
		res.Entries = append(res.Entries, &agentv1.LogEntry{
			Time: e.time(), Priority: uint32(prio), Unit: e.Unit, Identifier: e.Identifier, //nolint:gosec // 0-7
			Pid: int32(pid), Message: truncate(msg, maxLogMessage),
		})
	}
	if len(res.Entries) > limit {
		res.Entries = res.Entries[len(res.Entries)-limit:]
	}
	return res, nil
}

var (
	sshAccepted    = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	sshFailedInv   = regexp.MustCompile(`^Failed (\S+) for invalid user (\S*) from (\S+) port \d+`)
	sshFailed      = regexp.MustCompile(`^Failed (\S+) for (\S+) from (\S+) port \d+`)
	sshInvalidUser = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	sudoLine       = regexp.MustCompile(`^\s*(\S+) : (.*)$`)
)

// ParseAuthEvent turns one sshd or sudo journal message into an event, or returns
// false for messages that are not login or sudo records.
func ParseAuthEvent(identifier, msg string) (*agentv1.AuthEvent, bool) {
	ev := &agentv1.AuthEvent{Message: truncate(msg, maxLogMessage)}
	switch {
	case strings.HasPrefix(identifier, "sshd"):
		if m := sshAccepted.FindStringSubmatch(msg); m != nil {
			ev.Kind, ev.Method, ev.User, ev.SourceIp = agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_ACCEPTED, m[1], m[2], m[3]
		} else if m := sshFailedInv.FindStringSubmatch(msg); m != nil {
			ev.Kind, ev.Method, ev.User, ev.SourceIp = agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_INVALID_USER, m[1], m[2], m[3]
		} else if m := sshFailed.FindStringSubmatch(msg); m != nil {
			ev.Kind, ev.Method, ev.User, ev.SourceIp = agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_FAILED, m[1], m[2], m[3]
		} else if m := sshInvalidUser.FindStringSubmatch(msg); m != nil {
			ev.Kind, ev.User, ev.SourceIp = agentv1.AuthEventKind_AUTH_EVENT_KIND_SSH_INVALID_USER, m[1], m[2]
		} else {
			return nil, false
		}
		return ev, true
	case identifier == "sudo":
		m := sudoLine.FindStringSubmatch(msg)
		if m == nil {
			return nil, false
		}
		ev.User = m[1]
		fields := map[string]string{}
		for _, part := range strings.Split(m[2], " ; ") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
				fields[k] = v
			}
		}
		cmdline, ok := fields["COMMAND"]
		if !ok {
			return nil, false
		}
		ev.Command, ev.TargetUser = cmdline, fields["USER"]
		ev.Kind = agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO
		lower := strings.ToLower(m[2])
		if strings.Contains(lower, "not in sudoers") || strings.Contains(lower, "incorrect password") ||
			strings.Contains(lower, "command not allowed") || strings.Contains(lower, "authentication failure") {
			ev.Kind = agentv1.AuthEventKind_AUTH_EVENT_KIND_SUDO_FAILED
		}
		return ev, true
	}
	return nil, false
}

// AuthLog returns SSH login and sudo events, oldest first.
func (j Journal) AuthLog(ctx context.Context, req *agentv1.AuthLogRequest) (*agentv1.AuthLogResult, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, maxLogLines)
	since := req.GetSinceSeconds()
	if since == 0 {
		since = 86400
	}
	// Repeating a field match ORs the values. OpenSSH 9.8+ logs as sshd-session.
	entries, err := j.run(ctx, []string{
		"--since=-" + strconv.FormatUint(uint64(since), 10) + "s",
		"--lines=" + strconv.Itoa(limit*grepScanFactor),
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo",
	})
	if err != nil {
		return nil, err
	}
	res := &agentv1.AuthLogResult{}
	for _, e := range entries {
		if ev, ok := ParseAuthEvent(e.Identifier, e.message()); ok {
			ev.Time = e.time()
			res.Events = append(res.Events, ev)
		}
	}
	if len(res.Events) > limit {
		res.Events = res.Events[len(res.Events)-limit:]
	}
	return res, nil
}
