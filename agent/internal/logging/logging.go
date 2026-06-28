// Package logging configures the process-wide slog logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Setup builds a slog.Logger for the given level and format and installs it as
// the default. format is "text" or "json"; anything else falls back to text.
// When filePath is non-empty, slog output is duplicated to that file (append).
func Setup(level, format, filePath string) (*slog.Logger, error) {
	out := io.Writer(os.Stderr)
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		out = io.MultiWriter(os.Stderr, f)
	}
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(out, opts)
	} else {
		h = slog.NewTextHandler(out, opts)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
