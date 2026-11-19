// Package logging builds the structured slog logger shared by all binaries.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Config selects log level and output format.
type Config struct {
	Level  string `yaml:"level" env:"LOG_LEVEL"`   // debug, info, warn, error
	Format string `yaml:"format" env:"LOG_FORMAT"` // json, text
}

// New returns a logger writing to w.
func New(w io.Writer, cfg Config) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q", cfg.Level)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(cfg.Format) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q", cfg.Format)
	}
}
