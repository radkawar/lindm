package nativeexec

import "bytes"

// Buffer retains at most its limit of written bytes, either the first (head) or
// the most recent (tail), and records that the rest was discarded. Writes never
// fail: a verbose child is drained to completion instead of being blocked or
// killed by SIGPIPE in the middle of a native transaction. Callers decide
// whether truncated output is acceptable. It is the one bounded capture writer
// for agent and lab subprocesses; it is not safe for concurrent writers.
type Buffer struct {
	// A named field, not an embedded bytes.Buffer: io.Copy must not bypass
	// Write through a promoted ReadFrom.
	data      bytes.Buffer
	limit     int
	tail      bool
	truncated bool
}

// NewBuffer returns a Buffer that retains the first limit bytes.
func NewBuffer(limit int) *Buffer { return &Buffer{limit: max(limit, 0)} }

// NewTailBuffer returns a Buffer that retains the last limit bytes, for
// diagnostics where a verbose tool's terminal error matters most.
func NewTailBuffer(limit int) *Buffer { return &Buffer{limit: max(limit, 0), tail: true} }

func (b *Buffer) Write(p []byte) (int, error) {
	n := len(p)
	if !b.tail {
		keep := min(n, b.limit-b.data.Len())
		b.truncated = b.truncated || keep < n
		b.data.Write(p[:keep])
		return n, nil
	}
	if n >= b.limit {
		b.truncated = b.truncated || n > b.limit || b.data.Len() > 0
		b.data.Reset()
		b.data.Write(p[n-b.limit:])
		return n, nil
	}
	if drop := b.data.Len() + n - b.limit; drop > 0 {
		b.truncated = true
		kept := b.data.Bytes()[drop:]
		copy(b.data.Bytes(), kept)
		b.data.Truncate(len(kept))
	}
	b.data.Write(p)
	return n, nil
}

// Bytes returns the retained bytes. It aliases the buffer.
func (b *Buffer) Bytes() []byte { return b.data.Bytes() }

// String returns the retained bytes.
func (b *Buffer) String() string { return b.data.String() }

// Len reports the retained length.
func (b *Buffer) Len() int { return b.data.Len() }

// Truncated reports whether any written byte was discarded.
func (b *Buffer) Truncated() bool { return b.truncated }
