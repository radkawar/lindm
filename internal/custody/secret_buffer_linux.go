// SPDX-License-Identifier: Apache-2.0
//go:build linux

package custody

import (
	"errors"

	"golang.org/x/sys/unix"
)

// SecretBuffer owns non-swappable, non-dumpable memory for lindm-owned inputs.
// It does not protect copies made by cryptographic libraries; establish the
// release swap policy separately before admitting secrets. Close wipes first.
// Callers must stop using Bytes before Close; the buffer is not concurrent-safe.
type SecretBuffer struct{ data []byte }

// NewSecretBuffer allocates and locks a bounded dedicated anonymous mapping.
func NewSecretBuffer(size int) (*SecretBuffer, error) {
	if size < 1 || size > 4<<20 {
		return nil, errors.New("custody: secret buffer size outside 1..4194304")
	}
	data, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	if err := unix.Madvise(data, unix.MADV_DONTDUMP); err != nil {
		return nil, errors.Join(err, unix.Munmap(data))
	}
	if err := unix.Mlock(data); err != nil {
		return nil, errors.Join(err, unix.Munmap(data))
	}
	return &SecretBuffer{data: data}, nil
}

// Bytes returns the owned mapping, valid only until Close.
func (b *SecretBuffer) Bytes() []byte { return b.data }

// Close wipes and releases the mapping. Repeated calls are harmless.
func (b *SecretBuffer) Close() error {
	if b == nil || b.data == nil {
		return nil
	}
	clear(b.data)
	err := errors.Join(unix.Munlock(b.data), unix.Munmap(b.data))
	b.data = nil
	return err
}
