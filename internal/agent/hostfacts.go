package agent

import (
	"bufio"
	"bytes"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// collectHostFacts gathers basic facts about the host. Missing files are ignored so the
// agent still starts on unusual systems.
func collectHostFacts() *agentv1.HostFacts {
	f := &agentv1.HostFacts{Os: runtime.GOOS, Arch: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		f.Hostname = h
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		rel := parseOSRelease(b)
		f.Distro, f.DistroVersion = rel["ID"], rel["VERSION_ID"]
	}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		if bt, ok := parseBootTime(b); ok {
			f.BootTime = timestamppb.New(bt)
		}
	}
	return f
}

func parseOSRelease(b []byte) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `'"`)
		}
		out[k] = v
	}
	return out
}

func parseBootTime(b []byte) (time.Time, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(sec, 0), true
		}
	}
	return time.Time{}, false
}
