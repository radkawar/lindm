//go:build linux

package osupdate

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/nativeexec"
)

const (
	diagnosticLines     = 8
	diagnosticLineBytes = 512
	outputTailBytes     = 64 << 10
	redactedLine        = "[redacted sensitive native output]"
)

var (
	nativeURL       = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s<>"']+|[^\s<>"']*[?@][^\s<>"']*`)
	nativeSensitive = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|secret|token|authorization|proxy-authorization|cookie|credentials?|api[-_]?key|access[-_]?key|private[-_]?key|bearer|basic)\b|[a-z_][a-z0-9_:.-]*\s*=`)
)

// outputCapture keeps the most recent bytes of a native stream for
// diagnostics, independently of nativeexec's bounded stdout used for parsing,
// so a verbose tool cannot hide its final error.
type outputCapture struct{ buf *nativeexec.Buffer }

func newOutputCapture() *outputCapture {
	return &outputCapture{buf: nativeexec.NewTailBuffer(outputTailBytes)}
}

func (c *outputCapture) Write(p []byte) (int, error) { return c.buf.Write(p) }

// cut reports that older output was discarded.
func (c *outputCapture) cut() bool { return c.buf.Truncated() }

// tailLines returns the complete retained lines; a partial first line after
// rotation may start inside a credential or escape sequence and is dropped.
func (c *outputCapture) tailLines() []string {
	text := c.buf.String()
	if c.cut() {
		_, rest, ok := strings.Cut(text, "\n")
		if !ok {
			return nil
		}
		text = rest
	}
	return strings.Split(text, "\n")
}

// sanitizeLines removes escapes and control characters, redacts URLs,
// assignments and credential-looking lines, and suppresses PEM blocks.
func sanitizeLines(lines []string) ([]string, bool) {
	var out []string
	truncated := false
	inPEM := false
	for _, line := range lines {
		if strings.Contains(line, "-----BEGIN ") {
			inPEM = true
			out = append(out, redactedLine)
			continue
		}
		if inPEM {
			if strings.Contains(line, "-----END ") {
				inPEM = false
			}
			continue
		}
		clean, cut := sanitizeLine(line)
		truncated = truncated || cut
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out, truncated
}

func sanitizeLine(line string) (string, bool) {
	// Consume complete ANSI CSI and string escapes, including OSC hyperlinks:
	// removing only ESC would expose hidden OSC contents and spoofed text.
	var clean strings.Builder
	clean.Grow(len(line))
	for i := 0; i < len(line); {
		r, n := utf8.DecodeRuneInString(line[i:])
		i += n
		if r == '\x1b' && i < len(line) {
			r = rune(line[i])
			i++
			switch r {
			case '[':
				r = '\u009b'
			case ']', 'P', 'X', '^', '_':
				r = '\u009d'
			default:
				continue
			}
		}
		if r == '\u009b' {
			for i < len(line) {
				c := line[i]
				i++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			continue
		}
		if r == '\u009d' || r == '\u0090' || r == '\u0098' || r == '\u009e' || r == '\u009f' {
			for i < len(line) {
				c, size := utf8.DecodeRuneInString(line[i:])
				i += size
				if c == '\a' || c == '\u009c' {
					break
				}
				if c == '\x1b' && i < len(line) && line[i] == '\\' {
					i++
					break
				}
			}
			continue
		}
		if r == '\t' || r == '\r' {
			clean.WriteByte(' ')
		} else if !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) && r != utf8.RuneError {
			clean.WriteRune(r)
		}
	}
	value := strings.TrimSpace(clean.String())
	if nativeSensitive.MatchString(value) {
		value = redactedLine
	} else {
		value = nativeURL.ReplaceAllString(value, "[redacted-url]")
	}
	if len(value) <= diagnosticLineBytes {
		return value, false
	}
	end := diagnosticLineBytes
	for !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
}

// nativeDiagnostic keeps the final sanitized lines of stdout then stderr
// (stderr last, so its terminal error survives the eight-line bound). No
// argv, configuration or environment is ever added.
func nativeDiagnostic(tool agentv1.PatchRunTool, phase agentv1.PatchRunPhase, exitCode int, outputs ...*outputCapture) *agentv1.PatchRunDiagnostic {
	diagnostic := &agentv1.PatchRunDiagnostic{Tool: tool, Phase: phase, ExitCode: int32(max(-1, min(exitCode, 255)))}
	for _, output := range outputs {
		if output == nil {
			continue
		}
		lines, truncated := sanitizeLines(output.tailLines())
		diagnostic.Truncated = diagnostic.Truncated || truncated || output.cut()
		diagnostic.ErrorLines = append(diagnostic.ErrorLines, lines...)
	}
	if excess := len(diagnostic.ErrorLines) - diagnosticLines; excess > 0 {
		diagnostic.ErrorLines = diagnostic.ErrorLines[excess:]
		diagnostic.Truncated = true
	}
	return diagnostic
}

// runnerDiagnostic reports a lindm-side failure with a fixed message.
func runnerDiagnostic(tool agentv1.PatchRunTool, phase agentv1.PatchRunPhase, message string) *agentv1.PatchRunDiagnostic {
	line, _ := sanitizeLine(message)
	return &agentv1.PatchRunDiagnostic{Tool: tool, Phase: phase, ExitCode: -1, ErrorLines: []string{line}}
}
