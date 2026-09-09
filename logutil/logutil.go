// Package logutil prints human-readable, coloured logs to stderr.
//
// The three printf-style helpers are thin wrappers around log/slog, so the
// standard logging API is available (slog.Default() is set up by this package),
// while the output keeps the compact "level: message" shape that suits a CLI
// better than slog's default key=value rendering.
package logutil

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// EnableDebug turns Debugf on. Set from the --debug flag.
var EnableDebug = false

// Colours are disabled when stderr isn't a terminal (in Docker, or when the
// output is redirected to a file) and when NO_COLOR is set, see no-color.org.
// The logs used to carry raw escape codes in both cases.
var useColour = func() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}()

func colour(code string) func(string) string {
	return func(s string) string {
		if !useColour {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
}

var (
	Yel   = colour("33")
	Green = colour("32")
	Red   = colour("31")
	Bold  = colour("37;1")
	Gray  = colour("90")
	Cyan  = colour("36")
)

// Debugf prints to stderr, but only when EnableDebug is set.
func Debugf(format string, a ...any) {
	logf(slog.LevelDebug, format, a...)
}

// Errorf prints to stderr.
func Errorf(format string, a ...any) {
	logf(slog.LevelError, format, a...)
}

// Infof prints to stderr.
func Infof(format string, a ...any) {
	logf(slog.LevelInfo, format, a...)
}

func logf(level slog.Level, format string, a ...any) {
	l := slog.Default()
	if !l.Enabled(context.Background(), level) {
		return
	}
	l.Log(context.Background(), level, fmt.Sprintf(format, a...))
}

func init() {
	slog.SetDefault(slog.New(&handler{w: os.Stderr}))
}

// handler renders records as "level: message", followed by any attributes.
type handler struct {
	w      io.Writer
	prefix string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	if level <= slog.LevelDebug {
		return EnableDebug
	}
	return true
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var label string
	switch {
	case r.Level <= slog.LevelDebug:
		label = Gray("debug")
	case r.Level <= slog.LevelInfo:
		label = Yel("info")
	case r.Level <= slog.LevelWarn:
		label = Yel("warning")
	default:
		label = Red("error")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s%s", label, h.prefix, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
		return true
	})
	b.WriteString("\n")

	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	var b strings.Builder
	b.WriteString(h.prefix)
	for _, a := range attrs {
		fmt.Fprintf(&b, "%s=%v ", a.Key, a.Value)
	}
	return &handler{w: h.w, prefix: b.String()}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{w: h.w, prefix: h.prefix + name + "."}
}
