package ctl

import (
	"io"
	"strings"
	"unicode/utf8"
)

// Agents report text that ultimately comes from the managed server: process command
// lines, journal messages, container names and logs, error messages from Docker. Any of
// it may contain terminal escape sequences (cursor movement, OSC 52 clipboard writes,
// hyperlinks, title changes) or bidi controls that make output lie. Everything smctl
// prints from a result goes through these filters.

// unsafeRune reports runes that must not reach the operator's terminal: C0 controls
// other than tab and newline, DEL, C1 controls, and bidi embedding/isolate controls.
func unsafeRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// Sanitize removes unsafe runes from s.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return -1
		}
		return r
	}, s)
}

// Cell is cell for callers outside the package, e.g. one-line error messages.
func Cell(s string) string { return cell(s) }

// cell sanitizes s for a table cell: tabs and newlines would break the columns or fake
// extra rows, so they become spaces.
func cell(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return ' '
		case unsafeRune(r):
			return -1
		}
		return r
	}, s)
}

// SafeWriter wraps w and drops unsafe runes from everything written to it. Invalid
// UTF-8 is replaced. A rune split across writes is kept until it is complete.
func SafeWriter(w io.Writer) io.Writer { return &safeWriter{w: w} }

type safeWriter struct {
	w    io.Writer
	rest []byte
}

func (s *safeWriter) Write(p []byte) (int, error) {
	buf := append(s.rest, p...)
	s.rest = nil
	out := make([]byte, 0, len(buf))
	for len(buf) > 0 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size <= 1 {
			if !utf8.FullRune(buf) { // incomplete rune at the end: wait for more
				s.rest = append([]byte(nil), buf...)
				break
			}
			out = append(out, "�"...)
			buf = buf[1:]
			continue
		}
		if !unsafeRune(r) {
			out = append(out, buf[:size]...)
		}
		buf = buf[size:]
	}
	if _, err := s.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
