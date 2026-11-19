package agent

import "testing"

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease([]byte("# comment\nNAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nBAD LINE\nPRETTY='x y'\n"))
	if got["ID"] != "ubuntu" || got["VERSION_ID"] != "24.04" || got["NAME"] != "Ubuntu" || got["PRETTY"] != "x y" {
		t.Fatalf("parsed %v", got)
	}
}

func TestParseBootTime(t *testing.T) {
	bt, ok := parseBootTime([]byte("cpu  1 2 3\nbtime 1700000000\nprocesses 5\n"))
	if !ok || bt.Unix() != 1700000000 {
		t.Fatalf("got %v %v", bt, ok)
	}
	if _, ok := parseBootTime([]byte("cpu 1\n")); ok {
		t.Fatal("expected no boot time")
	}
}
