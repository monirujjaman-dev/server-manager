package ctl

import (
	"bytes"
	"testing"
)

func TestSanitize(t *testing.T) {
	evil := "ok\x1b]52;c;ZXZpbA==\x07\x1b[2Jhid\u202eden\r\u009bX\tend\n"
	if got, want := Sanitize(evil), "ok]52;c;ZXZpbA==[2Jhidden"+"X\tend\n"; got != want {
		t.Errorf("Sanitize = %q, want %q", got, want)
	}
	if got := cell("a\tb\nc\x1b"); got != "a b c" {
		t.Errorf("cell = %q", got)
	}
}

func TestSafeWriter(t *testing.T) {
	var buf bytes.Buffer
	w := SafeWriter(&buf)
	// "é" split across two writes, an escape sequence, and invalid UTF-8.
	for _, p := range [][]byte{[]byte("caf\xc3"), []byte("\xa9 \x1b[31mred\n"), []byte("bad\xffbyte")} {
		n, err := w.Write(p)
		if err != nil || n != len(p) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if got, want := buf.String(), "café [31mred\nbad�byte"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
