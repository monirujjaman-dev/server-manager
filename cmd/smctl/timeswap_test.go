package main

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]uint32{"2G": 2048, "2g": 2048, "512M": 512, "512MB": 512, "1GB": 1024, "64": 64, "64G": 65536} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1T", "63M", "65G", "-1G", "2.5G", "G", "abc"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}
