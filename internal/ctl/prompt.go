package ctl

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

var (
	stdinOnce   sync.Once
	stdinReader *bufio.Reader
)

func stdin() *bufio.Reader {
	stdinOnce.Do(func() { stdinReader = bufio.NewReader(os.Stdin) })
	return stdinReader
}

// ReadLine prints prompt to w and reads one line from standard input.
func ReadLine(w io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(w, prompt)
	line, err := stdin().ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadSecret reads a line without echo when standard input is a terminal. When it is
// not (scripts, tests), it reads a plain line.
func ReadSecret(w io.Writer, prompt string) (string, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // file descriptors fit int
	if !term.IsTerminal(fd) {
		return ReadLine(w, prompt)
	}
	_, _ = fmt.Fprint(w, prompt)
	b, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(w)
	return string(b), err
}
