package assistrelay

import (
	"fmt"
	"log/slog"

	"github.com/pion/logging"
)

// loggerFactory routes pion diagnostics into slog. Peer traffic can trigger
// pion warnings and errors at packet rate, so they are debug records here;
// the relay's own lifecycle is logged by Relay at info level.
type loggerFactory struct {
	logger *slog.Logger
}

func (f loggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return pionLogger{logger: f.logger.With("component", "assistrelay", "scope", scope)}
}

type pionLogger struct {
	logger *slog.Logger
}

var _ logging.LeveledLogger = pionLogger{}

func (pionLogger) Trace(string)          {}
func (pionLogger) Tracef(string, ...any) {}
func (pionLogger) Debug(string)          {}
func (pionLogger) Debugf(string, ...any) {}
func (pionLogger) Info(string)           {}
func (pionLogger) Infof(string, ...any)  {}

func (l pionLogger) Warn(msg string) { l.logger.Debug(msg, "pion_level", "warn") }
func (l pionLogger) Warnf(format string, args ...any) {
	l.logger.Debug(fmt.Sprintf(format, args...), "pion_level", "warn")
}
func (l pionLogger) Error(msg string) { l.logger.Debug(msg, "pion_level", "error") }
func (l pionLogger) Errorf(format string, args ...any) {
	l.logger.Debug(fmt.Sprintf(format, args...), "pion_level", "error")
}
