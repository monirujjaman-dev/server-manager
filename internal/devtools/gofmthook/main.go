// Command gofmthook is a Claude Code PostToolUse hook that gofmt's a Go file after it is
// written or edited. It reads the hook payload from stdin, so it works the same on
// Windows, macOS and Linux without jq or a POSIX shell.
//
// It never fails the tool call: files that are not Go, are generated, or do not parse
// are left alone, and errors are ignored.
package main

import (
	"bytes"
	"encoding/json"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

type payload struct {
	ToolInput struct {
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
	ToolResponse struct {
		FilePath string `json:"filePath"`
	} `json:"tool_response"`
}

func main() {
	var p payload
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return
	}
	path := p.ToolResponse.FilePath
	if path == "" {
		path = p.ToolInput.FilePath
	}
	if !strings.HasSuffix(path, ".go") || generated(path) || !inProject(path) {
		return
	}
	src, err := os.ReadFile(path) //nolint:gosec // checked by inProject
	if err != nil {
		return
	}
	out, err := format.Source(src)
	if err != nil || bytes.Equal(out, src) {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, out, info.Mode().Perm()) //nolint:gosec // checked by inProject
}

func generated(path string) bool {
	slash := filepath.ToSlash(path)
	return strings.Contains(slash, "/gen/") || strings.Contains(slash, "/store/db/") ||
		strings.HasSuffix(slash, ".pb.go") || strings.HasSuffix(slash, ".connect.go")
}

// inProject reports whether path is inside the working directory, which the hook command
// sets to the project root, so the hook never rewrites files elsewhere.
func inProject(path string) bool {
	root, err := os.Getwd()
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
