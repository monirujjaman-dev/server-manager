package modules

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	agentv1 "github.com/monirujjaman-dev/server-manager/gen/sm/agent/v1"
)

// fakeEngine is a tiny Docker Engine API with one container "web".
type fakeEngine struct {
	t       *testing.T
	api     string
	tty     bool
	mu      sync.Mutex
	calls   []string // "METHOD path?query" after version negotiation
	state   string
	logBody []byte
}

const webID = "3f2a9c0d1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5"

func newFakeEngine(t *testing.T, api string) (*fakeEngine, *Docker) {
	f := &fakeEngine{t: t, api: api, state: "running"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, NewDockerHTTP(srv.Client(), srv.URL)
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/version" {
		_ = json.NewEncoder(w).Encode(map[string]string{"ApiVersion": f.api})
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	path := r.URL.Path[strings.Index(r.URL.Path[1:], "/")+1:] // strip /v1.xx
	switch {
	case path == "/containers/json":
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": webID, "Names": []string{"/web"}, "Image": "nginx:1.27", "State": f.state, "Status": "Up 3 hours", "Created": 1700000000,
				"Ports": []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}}},
		})
	case path == "/containers/web/json" || isIDPrefixPath(path):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id": webID, "Name": "/web", "Created": "2024-01-02T03:04:05.123456789Z",
			"State":  map[string]any{"Status": f.state, "Health": map[string]string{"Status": "healthy"}},
			"Config": map[string]any{"Image": "nginx:1.27", "Tty": f.tty},
		})
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"No such container: nope"}`))
	case path == "/containers/"+webID+"/stop":
		if f.state != "running" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		f.state = "exited"
		w.WriteHeader(http.StatusNoContent)
	case path == "/containers/"+webID && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	case path == "/containers/"+webID+"/logs":
		_, _ = w.Write(f.logBody)
	case path == "/containers/"+webID+"/stats":
		_, _ = w.Write([]byte(`{"id":"` + webID + `","name":"/web",
			"cpu_stats":{"cpu_usage":{"total_usage":3000000000},"system_cpu_usage":20000000000,"online_cpus":4},
			"precpu_stats":{"cpu_usage":{"total_usage":2000000000},"system_cpu_usage":10000000000},
			"memory_stats":{"usage":500,"limit":1000,"stats":{"inactive_file":100}},
			"networks":{"eth0":{"rx_bytes":10,"tx_bytes":20},"eth1":{"rx_bytes":1,"tx_bytes":2}},
			"blkio_stats":{"io_service_bytes_recursive":[{"op":"read","value":7},{"op":"Write","value":9}]},
			"pids_stats":{"current":3}}`))
	case path == "/volumes/prune":
		_, _ = w.Write([]byte(`{"VolumesDeleted":["data1"],"SpaceReclaimed":4096}`))
	case path == "/images/prune":
		_, _ = w.Write([]byte(`{"ImagesDeleted":[{"Untagged":"old:1"},{"Deleted":"sha256:abc"}],"SpaceReclaimed":123}`))
	case path == "/images/json":
		_, _ = w.Write([]byte(`[{"Id":"sha256:1","RepoTags":["<none>:<none>"],"Size":10,"Created":1,"Containers":-1},
			{"Id":"sha256:2","RepoTags":["nginx:1.27"],"Size":20,"Created":2,"Containers":1}]`))
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// isIDPrefixPath matches /containers/<prefix of webID>/json, as Docker resolves prefixes.
func isIDPrefixPath(path string) bool {
	ref, ok := strings.CutSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
	return ok && len(ref) >= 4 && strings.HasPrefix(webID, ref)
}

func (f *fakeEngine) lastCall() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func TestDockerVersionNegotiation(t *testing.T) {
	for _, tc := range []struct{ daemon, want, wantErr string }{
		{daemon: "1.51", want: "/v1.47/"},
		{daemon: "1.44", want: "/v1.44/"},
		{daemon: "1.41", want: "/v1.41/"},
		{daemon: "1.40", wantErr: "too old"},
	} {
		f, d := newFakeEngine(t, tc.daemon)
		_, err := d.ListContainers(context.Background(), &agentv1.DockerContainerListRequest{All: true})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("daemon %s: error %v, want %q", tc.daemon, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if c := f.lastCall(); !strings.Contains(c, tc.want) || !strings.Contains(c, "all=1") {
			t.Errorf("daemon %s: request %q, want %s and all=1", tc.daemon, c, tc.want)
		}
	}
}

func TestDockerListAndControl(t *testing.T) {
	f, d := newFakeEngine(t, "1.47")
	ctx := context.Background()
	list, err := d.ListContainers(ctx, &agentv1.DockerContainerListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	c := list.GetContainers()[0]
	if c.GetName() != "web" || c.GetPorts()[0].GetPublicPort() != 8080 || c.GetCreated().GetSeconds() != 1700000000 {
		t.Fatalf("container = %v", c)
	}

	res, err := d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{
		Container: "web", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP, TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetContainer().GetState() != "exited" || res.GetContainer().GetStatus() != "exited (healthy)" {
		t.Fatalf("after stop: %v", res.GetContainer())
	}
	f.mu.Lock()
	stopCall := f.calls[2] // list, lookup, stop
	f.mu.Unlock()
	// The stop goes to the full ID resolved by the lookup, not to the name.
	if stopCall != "POST /v1.47/containers/"+webID+"/stop?t=5" {
		t.Fatalf("stop request %q", stopCall)
	}
	// Stopping again is a 304 from Docker and not an error.
	if _, err := d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{
		Container: "web", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP,
	}); err != nil {
		t.Fatalf("second stop: %v", err)
	}

	res, err = d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{
		Container: "web", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE, Force: true, RemoveVolumes: true,
	})
	if err != nil || res.GetContainer().GetId() != webID {
		t.Fatalf("remove: %v %v", res, err)
	}
	if c := f.lastCall(); c != "DELETE /v1.47/containers/"+webID+"?force=1&v=1" {
		t.Fatalf("remove request %q", c)
	}

	_, err = d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{
		Container: "nope", Operation: agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_REMOVE,
	})
	if err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Fatalf("unknown container: %v", err)
	}
	if c := f.lastCall(); strings.HasPrefix(c, "DELETE") {
		t.Fatal("remove was sent for a container that failed lookup")
	}
	// A bad reference never reaches the daemon, even if Validate was bypassed.
	n := len(f.calls)
	if _, err := d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{Container: "../images", Operation: 1}); err == nil {
		t.Fatal("bad reference accepted")
	}
	if len(f.calls) != n {
		t.Fatal("bad reference was sent to the daemon")
	}
}

func frame(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s))) //nolint:gosec // test data
	return append(h, s...)
}

func TestDockerLogs(t *testing.T) {
	f, d := newFakeEngine(t, "1.47")
	var body bytes.Buffer
	body.Write(frame(1, "2024-01-02T03:04:05.000000001Z hello\n"))
	body.Write(frame(2, "2024-01-02T03:04:06Z oops "))        // a line split over two frames
	body.Write(frame(2, "continued\n2024-01-02T03:04:07Z x")) // and a final line without newline
	body.Write(frame(1, "2024-01-02T03:04:08Z "+strings.Repeat("é", 600)+"\n"))
	f.logBody = body.Bytes()
	res, err := d.Logs(context.Background(), &agentv1.DockerLogsRequest{Container: "web", Tail: 10, SinceSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if c := f.lastCall(); !strings.Contains(c, "tail=10") || !strings.Contains(c, "since=") || !strings.Contains(c, "timestamps=1") {
		t.Fatalf("logs request %q", c)
	}
	got := res.GetLines()
	if len(got) != 4 {
		t.Fatalf("%d lines: %v", len(got), got)
	}
	if got[0].GetMessage() != "hello" || got[0].GetStream() != "stdout" || got[0].GetTime().GetNanos() != 1 {
		t.Errorf("line 0 = %v", got[0])
	}
	if got[1].GetMessage() != "oops continued" || got[1].GetStream() != "stderr" {
		t.Errorf("line 1 = %v", got[1])
	}
	if len(got[2].GetMessage()) > dockerMaxLogLine || !strings.HasPrefix(got[2].GetMessage(), "éé") {
		t.Errorf("long line not truncated on a rune boundary: %d bytes", len(got[2].GetMessage()))
	}
	if got[3].GetMessage() != "x" || got[3].GetStream() != "stderr" {
		t.Errorf("trailing line = %v", got[3])
	}

	f.tty = true
	f.logBody = []byte("2024-01-02T03:04:05Z one\r\n2024-01-02T03:04:06Z two\n")
	res, err = d.Logs(context.Background(), &agentv1.DockerLogsRequest{Container: "web", Tail: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetLines()) != 1 || res.GetLines()[0].GetMessage() != "two" {
		t.Fatalf("tty logs = %v", res.GetLines())
	}
}

func TestDockerStats(t *testing.T) {
	_, d := newFakeEngine(t, "1.47")
	res, err := d.Stats(context.Background(), &agentv1.DockerStatsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s := res.GetStats()[0]
	// (3e9-2e9) / (20e9-10e9) * 4 CPUs * 100 = 40 %
	if s.GetCpuPercent() != 40 || s.GetMemoryUsageBytes() != 400 || s.GetMemoryLimitBytes() != 1000 ||
		s.GetNetRxBytes() != 11 || s.GetNetTxBytes() != 22 || s.GetBlockReadBytes() != 7 || s.GetBlockWriteBytes() != 9 ||
		s.GetPids() != 3 || s.GetName() != "web" {
		t.Fatalf("stats = %v", s)
	}
}

func TestDockerPrune(t *testing.T) {
	f, d := newFakeEngine(t, "1.47")
	ctx := context.Background()
	res, err := d.Prune(ctx, &agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetDeletedCount() != 1 || res.GetSpaceReclaimedBytes() != 4096 {
		t.Fatalf("prune = %v", res)
	}
	if c := f.lastCall(); strings.Contains(c, "filters") {
		t.Fatalf("anonymous-only prune sent filters: %q", c)
	}
	if _, err := d.Prune(ctx, &agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES, AllVolumes: true}); err != nil {
		t.Fatal(err)
	}
	if c := f.lastCall(); !strings.Contains(c, "filters=%7B%22all%22%3A%5B%22true%22%5D%7D") {
		t.Fatalf("all-volumes prune request %q", c)
	}
	res, err = d.Prune(ctx, &agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_IMAGES, AllImages: true})
	if err != nil || res.GetDeletedCount() != 2 || res.GetDeleted()[0] != "sha256:abc" && res.GetDeleted()[1] != "sha256:abc" {
		t.Fatalf("image prune = %v %v", res, err)
	}

	// On API 1.41 volume prune would also delete named volumes: refused, nothing sent.
	f, d = newFakeEngine(t, "1.41")
	if _, err := d.Prune(ctx, &agentv1.DockerPruneRequest{Target: agentv1.DockerPruneTarget_DOCKER_PRUNE_TARGET_VOLUMES}); err == nil ||
		!strings.Contains(err.Error(), "1.42") {
		t.Fatalf("old API volume prune: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("requests sent: %v", f.calls)
	}
}

func TestDockerImages(t *testing.T) {
	_, d := newFakeEngine(t, "1.47")
	res, err := d.ListImages(context.Background(), &agentv1.DockerImageListRequest{})
	if err != nil {
		t.Fatal(err)
	}
	im := res.GetImages()
	if len(im) != 2 || im[0].GetId() != "sha256:2" || len(im[1].GetTags()) != 0 {
		t.Fatalf("images = %v", im)
	}
}

func TestDockerUnavailable(t *testing.T) {
	d := NewDocker(t.TempDir() + "/missing.sock")
	_, err := d.ListContainers(context.Background(), &agentv1.DockerContainerListRequest{})
	if !errors.Is(err, ErrDockerUnavailable) {
		t.Fatalf("error = %v, want ErrDockerUnavailable", err)
	}
}

func TestDockerRefMustNotMatchOnlyByShortPrefix(t *testing.T) {
	f, d := newFakeEngine(t, "1.47")
	ctx := context.Background()
	stop := agentv1.DockerContainerOperation_DOCKER_CONTAINER_OPERATION_STOP
	// The fake resolves the full ID; a 6-character prefix is refused before acting.
	c := dockerInspectJSON{ID: webID, Name: "/web"}
	if err := matchesRef("3f2a9c", c); err == nil || !strings.Contains(err.Error(), "web") {
		t.Fatalf("short prefix accepted: %v", err)
	}
	for _, ok := range []string{"web", webID, webID[:12]} {
		if err := matchesRef(ok, c); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	if _, err := d.ControlContainer(ctx, &agentv1.DockerContainerControlRequest{Container: webID[:12], Operation: stop}); err != nil {
		t.Fatalf("12-char prefix: %v", err)
	}
	f.mu.Lock()
	calls := strings.Join(f.calls, " | ")
	f.mu.Unlock()
	if !strings.Contains(calls, "/containers/"+webID+"/stop") {
		t.Fatalf("stop not sent to the full ID: %s", calls)
	}
}

func TestDockerTTYLogLongLine(t *testing.T) {
	long := strings.Repeat("x", 200<<10) // longer than the reader's buffer
	lines, err := parseDockerLogs(strings.NewReader("2024-01-02T03:04:05Z "+long+"\n2024-01-02T03:04:06Z next\nlast"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || len(lines[0].GetMessage()) != dockerMaxLogLine || lines[1].GetMessage() != "next" || lines[2].GetMessage() != "last" {
		t.Fatalf("lines: %d, first %d bytes", len(lines), len(lines[0].GetMessage()))
	}
}

func TestDockerListBudget(t *testing.T) {
	var b budget
	tags := make([]string, dockerMaxTags)
	for i := range tags {
		tags[i] = strings.Repeat("t", dockerMaxField)
	}
	big := &agentv1.DockerImage{Tags: tags} // the largest image entry the client builds
	n := 0
	for b.fits(big) {
		n++
	}
	if n == 0 || n >= dockerMaxItems {
		t.Fatalf("budget allowed %d large items", n)
	}
	if clip("éé", 3) != "é" || clip("abc", 5) != "abc" {
		t.Fatal("clip must cut on rune boundaries")
	}
}
