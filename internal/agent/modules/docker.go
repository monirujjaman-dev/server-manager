package modules

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
	"github.com/monirujjaman-dev/server-manager/internal/command"
)

// Docker Engine API versions this client speaks. Docker 29 dropped versions below 1.44,
// so the client negotiates: it uses the daemon's version, capped at the newest one it
// was written against.
const (
	dockerMinAPI = "1.41"
	dockerMaxAPI = "1.47"
)

// Output limits.
const (
	dockerMaxItems       = 1000
	dockerMaxPorts       = 32
	dockerMaxTags        = 16
	dockerMaxDeleted     = 500
	dockerMaxStats       = 100
	dockerStatsParallel  = 8
	dockerMaxLogLine     = 1024
	dockerMaxLogBytes    = 4 << 20
	dockerMaxResponse    = 16 << 20
	dockerDefaultLogTail = 100
	// dockerMaxField caps names, images, statuses and paths taken from the daemon.
	dockerMaxField = 256
	// dockerListBudget keeps list results well inside the agent's result limit.
	dockerListBudget = 512 << 10
)

// clip truncates s to n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// budget tracks the encoded size of a list being built.
type budget struct{ used int }

// fits adds m's size and reports whether the list is still within dockerListBudget.
func (b *budget) fits(m proto.Message) bool {
	b.used += proto.Size(m) + 4
	return b.used <= dockerListBudget
}

// DefaultDockerSocket is where the Docker daemon listens on most distributions.
const DefaultDockerSocket = "/run/docker.sock"

// Docker is a minimal Docker Engine API client over the daemon's UNIX socket. It only
// issues the fixed requests below; no caller-supplied path or body reaches the daemon.
type Docker struct {
	hc   *http.Client
	base string

	mu      sync.Mutex
	version string // negotiated API version, e.g. "1.47"
}

// NewDocker returns a client for the daemon at socket.
func NewDocker(socket string) *Docker {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 4,
	}
	return NewDockerHTTP(&http.Client{Transport: tr}, "http://docker")
}

// NewDockerHTTP returns a client using hc and base (tests point it at an httptest server).
func NewDockerHTTP(hc *http.Client, base string) *Docker {
	return &Docker{hc: hc, base: strings.TrimRight(base, "/")}
}

// ErrDockerUnavailable is returned when the daemon cannot be reached.
var ErrDockerUnavailable = errors.New("docker is not running or not installed")

type dockerAPIError struct {
	status int
	msg    string
}

func (e *dockerAPIError) Error() string { return "docker: " + e.msg }

// apiVersion negotiates once per client; a failed negotiation is retried next time.
func (d *Docker) apiVersion(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.version != "" {
		return d.version, nil
	}
	var v struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := d.raw(ctx, http.MethodGet, "/version", nil, &v); err != nil {
		return "", err
	}
	ver := v.APIVersion
	if versionLess(dockerMaxAPI, ver) {
		ver = dockerMaxAPI
	}
	if versionLess(ver, dockerMinAPI) {
		return "", fmt.Errorf("docker API %s is too old (need %s or newer)", v.APIVersion, dockerMinAPI)
	}
	d.version = ver
	return ver, nil
}

// versionLess compares "major.minor" API versions numerically.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa[0] != pb[0] {
		return pa[0] < pb[0]
	}
	return pa[1] < pb[1]
}

func versionParts(v string) [2]int {
	major, minor, _ := strings.Cut(v, ".")
	a, _ := strconv.Atoi(major)
	b, _ := strconv.Atoi(minor)
	return [2]int{a, b}
}

// call makes a versioned request and decodes a JSON response into out (if non-nil).
func (d *Docker) call(ctx context.Context, method, path string, q url.Values, out any) error {
	ver, err := d.apiVersion(ctx)
	if err != nil {
		return err
	}
	return d.raw(ctx, method, "/v"+ver+path, q, out)
}

func (d *Docker) open(ctx context.Context, method, path string, q url.Values) (*http.Response, error) {
	u := d.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w (%w)", ErrDockerUnavailable, err)
	}
	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }()
		var e struct {
			Message string `json:"message"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if json.Unmarshal(b, &e) != nil || e.Message == "" {
			e.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, &dockerAPIError{status: resp.StatusCode, msg: e.Message}
	}
	return resp, nil
}

func (d *Docker) raw(ctx context.Context, method, path string, q url.Values, out any) error {
	resp, err := d.open(ctx, method, path, q)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// 204 No Content and 304 Not Modified (already started/stopped) carry no body.
	if out == nil || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, dockerMaxResponse)).Decode(out); err != nil {
		return fmt.Errorf("docker: decode %s: %w", path, err)
	}
	return nil
}

// containerPath builds /containers/<ref><suffix>. Refs are validated by
// command.ValidateContainerRef; the check is repeated here so this function is safe on
// its own, and the ref is escaped regardless.
func containerPath(ref, suffix string) (string, error) {
	if err := command.ValidateContainerRef(ref); err != nil {
		return "", err
	}
	return "/containers/" + url.PathEscape(ref) + suffix, nil
}

type dockerContainerJSON struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Created int64    `json:"Created"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort uint32 `json:"PrivatePort"`
		PublicPort  uint32 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

func (c dockerContainerJSON) proto() *agentv1.DockerContainer {
	out := &agentv1.DockerContainer{
		Id: clip(c.ID, 64), Image: clip(c.Image, dockerMaxField), State: clip(c.State, 32), Status: clip(c.Status, dockerMaxField),
		Created: timestamppb.New(time.Unix(c.Created, 0)),
	}
	if len(c.Names) > 0 {
		out.Name = clip(strings.TrimPrefix(c.Names[0], "/"), dockerMaxField)
	}
	for i, p := range c.Ports {
		if i == dockerMaxPorts {
			break
		}
		out.Ports = append(out.Ports, &agentv1.DockerPort{Ip: clip(p.IP, 64), PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Protocol: clip(p.Type, 8)})
	}
	return out
}

func (d *Docker) listContainers(ctx context.Context, all bool) ([]dockerContainerJSON, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	var list []dockerContainerJSON
	if err := d.call(ctx, http.MethodGet, "/containers/json", q, &list); err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return firstName(list[i]) < firstName(list[j]) })
	return list, nil
}

func firstName(c dockerContainerJSON) string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return c.Names[0]
}

// ListContainers implements docker.list.
func (d *Docker) ListContainers(ctx context.Context, req *agentv1.DockerContainerListRequest) (*agentv1.DockerContainerListResult, error) {
	list, err := d.listContainers(ctx, req.GetAll())
	if err != nil {
		return nil, err
	}
	out := &agentv1.DockerContainerListResult{}
	var b budget
	for i, c := range list {
		p := c.proto()
		if i == dockerMaxItems || !b.fits(p) {
			out.Truncated = true
			break
		}
		out.Containers = append(out.Containers, p)
	}
	return out, nil
}

type dockerInspectJSON struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string `json:"Image"`
		Tty   bool   `json:"Tty"`
	} `json:"Config"`
}

func (d *Docker) inspect(ctx context.Context, ref string) (dockerInspectJSON, error) {
	var c dockerInspectJSON
	p, err := containerPath(ref, "/json")
	if err != nil {
		return c, err
	}
	return c, d.call(ctx, http.MethodGet, p, nil, &c)
}

func (c dockerInspectJSON) proto() *agentv1.DockerContainer {
	out := &agentv1.DockerContainer{Id: clip(c.ID, 64), Name: clip(strings.TrimPrefix(c.Name, "/"), dockerMaxField),
		Image: clip(c.Config.Image, dockerMaxField), State: clip(c.State.Status, 32), Status: clip(c.State.Status, 32)}
	if c.State.Health != nil && c.State.Health.Status != "" {
		out.Status += " (" + clip(c.State.Health.Status, 32) + ")"
	}
	if t, err := time.Parse(time.RFC3339Nano, c.Created); err == nil {
		out.Created = timestamppb.New(t)
	}
	return out
}

// ControlContainer implements docker.start/stop/restart/remove. The container is looked
// up first, so an unknown reference fails before anything changes.
func (d *Docker) ControlContainer(ctx context.Context, req *agentv1.DockerContainerControlRequest) (*agentv1.DockerContainerControlResult, error) {
	before, err := d.inspect(ctx, req.GetContainer())
	if err != nil {
		return nil, err
	}
	// Docker also resolves a reference by ID prefix, so "cafe" may name a container
	// called "cafe" or one whose ID starts with cafe. The operator confirmed the
	// reference they typed, so only an exact name or an unambiguous ID prefix is acted on.
	if err := matchesRef(req.GetContainer(), before); err != nil {
		return nil, err
	}
	// Act on the full ID from now on, so a name reused in between cannot redirect us.
	id := before.ID
	q := url.Values{}
	if t := req.GetTimeoutSeconds(); t > 0 {
		q.Set("t", strconv.FormatUint(uint64(t), 10))
	}
	var method, suffix string
	switch req.GetOperation() {
	case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_START:
		method, suffix = http.MethodPost, "/start"
	case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP:
		method, suffix = http.MethodPost, "/stop"
	case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_RESTART:
		method, suffix = http.MethodPost, "/restart"
	case agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE:
		method = http.MethodDelete
		if req.GetForce() {
			q.Set("force", "1")
		}
		if req.GetRemoveVolumes() {
			q.Set("v", "1")
		}
	default:
		return nil, errors.New("invalid container operation")
	}
	p, err := containerPath(id, suffix)
	if err != nil {
		return nil, err
	}
	if err := d.call(ctx, method, p, q, nil); err != nil {
		return nil, err
	}
	if method == http.MethodDelete {
		return &agentv1.DockerContainerControlResult{Container: before.proto()}, nil
	}
	after, err := d.inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	return &agentv1.DockerContainerControlResult{Container: after.proto()}, nil
}

// minIDPrefix is the shortest ID prefix accepted for changes (what `docker ps` shows).
const minIDPrefix = 12

func matchesRef(ref string, c dockerInspectJSON) error {
	name := strings.TrimPrefix(c.Name, "/")
	if ref == name || ref == c.ID || (len(ref) >= minIDPrefix && strings.HasPrefix(c.ID, ref)) {
		return nil
	}
	return fmt.Errorf("%q matched container %s (%s) by ID prefix; use its name or at least %d characters of its ID",
		ref, clip(name, dockerMaxField), clip(c.ID, minIDPrefix), minIDPrefix)
}

// Logs implements docker.logs.
func (d *Docker) Logs(ctx context.Context, req *agentv1.DockerLogsRequest) (*agentv1.DockerLogsResult, error) {
	c, err := d.inspect(ctx, req.GetContainer())
	if err != nil {
		return nil, err
	}
	tail := req.GetTail()
	if tail == 0 {
		tail = dockerDefaultLogTail
	}
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.FormatUint(uint64(tail), 10)}}
	if s := req.GetSinceSeconds(); s > 0 {
		q.Set("since", strconv.FormatInt(time.Now().Add(-time.Duration(s)*time.Second).Unix(), 10))
	}
	ver, err := d.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	p, err := containerPath(c.ID, "/logs")
	if err != nil {
		return nil, err
	}
	resp, err := d.open(ctx, http.MethodGet, "/v"+ver+p, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	lines, err := parseDockerLogs(io.LimitReader(resp.Body, dockerMaxLogBytes), c.Config.Tty)
	if err != nil {
		return nil, err
	}
	if len(lines) > int(tail) {
		lines = lines[len(lines)-int(tail):]
	}
	return &agentv1.DockerLogsResult{Lines: lines}, nil
}

// parseDockerLogs reads a logs stream. Without a TTY Docker multiplexes stdout and
// stderr in frames: 1 byte stream, 3 zero bytes, 4 bytes big-endian length, payload.
func parseDockerLogs(r io.Reader, tty bool) ([]*agentv1.DockerLogLine, error) {
	var out []*agentv1.DockerLogLine
	if tty {
		// Read line by line, keeping only the start of very long lines, so one huge
		// line cannot make the whole request fail.
		br := bufio.NewReaderSize(r, 64<<10)
		for {
			chunk, err := br.ReadSlice('\n')
			line := string(chunk[:min(len(chunk), 2*dockerMaxLogLine)])
			for errors.Is(err, bufio.ErrBufferFull) { // discard the rest of a long line
				_, err = br.ReadSlice('\n')
			}
			line = strings.TrimSuffix(line, "\n")
			if line != "" || err == nil {
				out = append(out, logLine("stdout", line))
			}
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if err != nil {
				return out, err
			}
		}
	}
	pending := map[string]*bytes.Buffer{"stdout": {}, "stderr": {}}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		buf := pending[stream]
		if _, err := io.CopyN(buf, r, int64(size)); err != nil {
			break // truncated by the size limit
		}
		for {
			line, err := buf.ReadString('\n')
			if err != nil { // incomplete line: keep it for the next frame
				rest := line
				buf.Reset()
				buf.WriteString(rest)
				break
			}
			out = append(out, logLine(stream, strings.TrimSuffix(line, "\n")))
		}
	}
	for _, stream := range []string{"stdout", "stderr"} {
		if rest := pending[stream].String(); rest != "" {
			out = append(out, logLine(stream, rest))
		}
	}
	return out, nil
}

// logLine splits Docker's RFC 3339 timestamp prefix from the message.
func logLine(stream, s string) *agentv1.DockerLogLine {
	l := &agentv1.DockerLogLine{Stream: stream}
	if ts, msg, ok := strings.Cut(s, " "); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			l.Time = timestamppb.New(t)
			s = msg
		}
	}
	s = strings.TrimSuffix(s, "\r")
	if len(s) > dockerMaxLogLine {
		s = s[:dockerMaxLogLine]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	l.Message = strings.ToValidUTF8(s, "�")
	return l
}

type dockerCPUJSON struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint32 `json:"online_cpus"`
}

type dockerStatsJSON struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	CPUStats    dockerCPUJSON `json:"cpu_stats"`
	PreCPUStats dockerCPUJSON `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlkioStats struct {
		IOServiceBytesRecursive []struct {
			Op    string `json:"op"`
			Value uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
	PidsStats struct {
		Current uint32 `json:"current"`
	} `json:"pids_stats"`
}

// proto computes the figures the way `docker stats` does.
func (s dockerStatsJSON) proto() *agentv1.DockerContainerStats {
	out := &agentv1.DockerContainerStats{Id: clip(s.ID, 64), Name: clip(strings.TrimPrefix(s.Name, "/"), dockerMaxField), Pids: s.PidsStats.Current,
		MemoryLimitBytes: s.MemoryStats.Limit}
	cpus := s.CPUStats.OnlineCPUs
	if cpus == 0 {
		cpus = uint32(len(s.CPUStats.CPUUsage.PercpuUsage)) //nolint:gosec // CPU counts fit uint32
	}
	cpu := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sys := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpu > 0 && sys > 0 {
		out.CpuPercent = cpu / sys * float64(cpus) * 100
	}
	// Page cache: inactive_file on cgroup v2, total_inactive_file or cache on v1.
	cache := s.MemoryStats.Stats["inactive_file"]
	if v, ok := s.MemoryStats.Stats["total_inactive_file"]; ok && cache == 0 {
		cache = v
	}
	if cache == 0 {
		cache = s.MemoryStats.Stats["cache"]
	}
	if s.MemoryStats.Usage > cache {
		out.MemoryUsageBytes = s.MemoryStats.Usage - cache
	}
	for _, n := range s.Networks {
		out.NetRxBytes += n.RxBytes
		out.NetTxBytes += n.TxBytes
	}
	for _, b := range s.BlkioStats.IOServiceBytesRecursive {
		switch strings.ToLower(b.Op) {
		case "read":
			out.BlockReadBytes += b.Value
		case "write":
			out.BlockWriteBytes += b.Value
		}
	}
	return out
}

// Stats implements docker.stats. Docker takes about a second per container to sample
// CPU, so containers are sampled in parallel.
func (d *Docker) Stats(ctx context.Context, req *agentv1.DockerStatsRequest) (*agentv1.DockerStatsResult, error) {
	var ids []string
	if ref := req.GetContainer(); ref != "" {
		c, err := d.inspect(ctx, ref)
		if err != nil {
			return nil, err
		}
		ids = []string{c.ID}
	} else {
		list, err := d.listContainers(ctx, false)
		if err != nil {
			return nil, err
		}
		for i, c := range list {
			if i == dockerMaxStats {
				break
			}
			ids = append(ids, c.ID)
		}
	}
	stats := make([]*agentv1.DockerContainerStats, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, dockerStatsParallel)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, err := containerPath(id, "/stats")
			if err != nil {
				errs[i] = err
				return
			}
			var s dockerStatsJSON
			if err := d.call(ctx, http.MethodGet, p, url.Values{"stream": {"false"}}, &s); err != nil {
				errs[i] = err
				return
			}
			stats[i] = s.proto()
		}()
	}
	wg.Wait()
	out := &agentv1.DockerStatsResult{}
	for i, s := range stats {
		if s != nil {
			out.Stats = append(out.Stats, s)
			continue
		}
		// A container that stopped while sampling is skipped; anything else is an error.
		var ae *dockerAPIError
		if !errors.As(errs[i], &ae) || ae.status != http.StatusNotFound || req.GetContainer() != "" {
			return nil, errs[i]
		}
	}
	return out, nil
}

// ListImages implements docker.images.
func (d *Docker) ListImages(ctx context.Context, _ *agentv1.DockerImageListRequest) (*agentv1.DockerImageListResult, error) {
	var list []struct {
		ID         string   `json:"Id"`
		RepoTags   []string `json:"RepoTags"`
		Size       int64    `json:"Size"`
		Created    int64    `json:"Created"`
		Containers int64    `json:"Containers"`
	}
	if err := d.call(ctx, http.MethodGet, "/images/json", nil, &list); err != nil {
		return nil, err
	}
	out := &agentv1.DockerImageListResult{}
	var b budget
	for i, im := range list {
		img := &agentv1.DockerImage{Id: clip(im.ID, 80), SizeBytes: uint64(max(im.Size, 0)), Created: timestamppb.New(time.Unix(im.Created, 0)), Containers: im.Containers}
		for _, t := range im.RepoTags {
			if t != "<none>:<none>" && len(img.Tags) < dockerMaxTags {
				img.Tags = append(img.Tags, clip(t, dockerMaxField))
			}
		}
		if i == dockerMaxItems || !b.fits(img) {
			out.Truncated = true
			break
		}
		out.Images = append(out.Images, img)
	}
	sort.Slice(out.Images, func(i, j int) bool {
		return out.Images[i].GetCreated().AsTime().After(out.Images[j].GetCreated().AsTime())
	})
	return out, nil
}

// ListVolumes implements docker.volumes.
func (d *Docker) ListVolumes(ctx context.Context, _ *agentv1.DockerVolumeListRequest) (*agentv1.DockerVolumeListResult, error) {
	var resp struct {
		Volumes []struct {
			Name       string `json:"Name"`
			Driver     string `json:"Driver"`
			Mountpoint string `json:"Mountpoint"`
			CreatedAt  string `json:"CreatedAt"`
		} `json:"Volumes"`
	}
	if err := d.call(ctx, http.MethodGet, "/volumes", nil, &resp); err != nil {
		return nil, err
	}
	sort.Slice(resp.Volumes, func(i, j int) bool { return resp.Volumes[i].Name < resp.Volumes[j].Name })
	out := &agentv1.DockerVolumeListResult{}
	var b budget
	for i, v := range resp.Volumes {
		vol := &agentv1.DockerVolume{Name: clip(v.Name, dockerMaxField), Driver: clip(v.Driver, 64), Mountpoint: clip(v.Mountpoint, dockerMaxField), CreatedAt: clip(v.CreatedAt, 64)}
		if i == dockerMaxItems || !b.fits(vol) {
			out.Truncated = true
			break
		}
		out.Volumes = append(out.Volumes, vol)
	}
	return out, nil
}

// ListNetworks implements docker.networks.
func (d *Docker) ListNetworks(ctx context.Context, _ *agentv1.DockerNetworkListRequest) (*agentv1.DockerNetworkListResult, error) {
	var list []struct {
		ID       string `json:"Id"`
		Name     string `json:"Name"`
		Driver   string `json:"Driver"`
		Scope    string `json:"Scope"`
		Internal bool   `json:"Internal"`
	}
	if err := d.call(ctx, http.MethodGet, "/networks", nil, &list); err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	out := &agentv1.DockerNetworkListResult{}
	var b budget
	for i, n := range list {
		nw := &agentv1.DockerNetwork{Id: clip(n.ID, 64), Name: clip(n.Name, dockerMaxField), Driver: clip(n.Driver, 64), Scope: clip(n.Scope, 32), Internal: n.Internal}
		if i == dockerMaxItems || !b.fits(nw) {
			out.Truncated = true
			break
		}
		out.Networks = append(out.Networks, nw)
	}
	return out, nil
}

// Prune implements docker.prune.
func (d *Docker) Prune(ctx context.Context, req *agentv1.DockerPruneRequest) (*agentv1.DockerPruneResult, error) {
	var resp struct {
		ContainersDeleted []string `json:"ContainersDeleted"`
		ImagesDeleted     []struct {
			Untagged string `json:"Untagged"`
			Deleted  string `json:"Deleted"`
		} `json:"ImagesDeleted"`
		NetworksDeleted []string `json:"NetworksDeleted"`
		VolumesDeleted  []string `json:"VolumesDeleted"`
		CachesDeleted   []string `json:"CachesDeleted"`
		SpaceReclaimed  int64    `json:"SpaceReclaimed"`
	}
	q := url.Values{}
	var path string
	switch req.GetTarget() {
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_CONTAINERS:
		path = "/containers/prune"
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES:
		path = "/images/prune"
		if req.GetAllImages() {
			q.Set("filters", `{"dangling":["false"]}`)
		}
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_NETWORKS:
		path = "/networks/prune"
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES:
		// Before API 1.42 volume prune also removed named volumes and could not be told
		// otherwise; refuse rather than delete more than was asked for.
		ver, err := d.apiVersion(ctx)
		if err != nil {
			return nil, err
		}
		if versionLess(ver, "1.42") {
			return nil, fmt.Errorf("pruning volumes needs Docker API 1.42 or newer (daemon speaks %s)", ver)
		}
		path = "/volumes/prune"
		if req.GetAllVolumes() {
			q.Set("filters", `{"all":["true"]}`)
		}
	case agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_BUILD_CACHE:
		path = "/build/prune"
	default:
		return nil, errors.New("invalid prune target")
	}
	if err := d.call(ctx, http.MethodPost, path, q, &resp); err != nil {
		return nil, err
	}
	deleted := append(append(append(resp.ContainersDeleted, resp.NetworksDeleted...), resp.VolumesDeleted...), resp.CachesDeleted...)
	for _, im := range resp.ImagesDeleted {
		if im.Deleted != "" {
			deleted = append(deleted, im.Deleted)
		} else if im.Untagged != "" {
			deleted = append(deleted, "untagged "+im.Untagged)
		}
	}
	out := &agentv1.DockerPruneResult{DeletedCount: uint32(len(deleted)), SpaceReclaimedBytes: uint64(max(resp.SpaceReclaimed, 0))} //nolint:gosec // bounded by the response size
	if len(deleted) > dockerMaxDeleted {
		deleted = deleted[:dockerMaxDeleted]
	}
	for i := range deleted {
		deleted[i] = clip(deleted[i], dockerMaxField)
	}
	out.Deleted = deleted
	return out, nil
}
