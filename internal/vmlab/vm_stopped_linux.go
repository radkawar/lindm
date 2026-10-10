//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type StoppedDiskSample struct {
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

type StoppedDiskSampleEvidence struct {
	SizeBytes int64               `json:"size_bytes"`
	Backend   string              `json:"backend"`
	Samples   []StoppedDiskSample `json:"samples"`
}

// stoppedDiskSamples observes logical bytes without guest software or a host
// block device. Three sampled regions are not proof of whole-drive sanitization.
func (v *guestVM) stoppedDiskSamples(ctx context.Context) (_ *StoppedDiskSampleEvidence, err error) {
	if v.done == nil || v.base == nil {
		return nil, errors.New("disk samples require an owned stopped guest and pinned base")
	}
	select {
	case <-v.done:
	default:
		return nil, errors.New("disk samples require stopped disk writers")
	}
	if err := encryptedPrivateDir(v.dir); err != nil {
		return nil, err
	}
	overlay, err := openRegular(filepath.Join(v.dir, "overlay.qcow2"))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, overlay.Close()) }()
	graph, err := stoppedDiskGraph(overlay, v.base)
	if err != nil {
		return nil, err
	}
	// qemu-img info intentionally opens without a backing chain; passing the
	// expanded graph makes its backing.* options invalid. Inspect the pinned
	// overlay alone for geometry; actual reads below use the explicit graph.
	overlayPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), overlay.Fd())
	infoJSON, err := encryptedHostOutput(ctx, v.dir, time.Minute, "qemu-img", "info", "-f", "qcow2", "--output=json", overlayPath)
	if err != nil {
		return nil, fmt.Errorf("inspect stopped disk: %w", err)
	}
	var info struct {
		Size int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(infoJSON, &info); err != nil {
		return nil, fmt.Errorf("decode stopped disk size: %w", err)
	}
	offsets, err := stoppedDiskSampleOffsets(info.Size)
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp(v.dir, ".sample-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(scratch)) }()
	result := &StoppedDiskSampleEvidence{SizeBytes: info.Size, Backend: "qemu-img-read-only", Samples: make([]StoppedDiskSample, 0, len(offsets))}
	for index, offset := range offsets {
		output := filepath.Join(scratch, strconv.Itoa(index))
		file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		// Limit the source itself to one region. qemu-img dd applies count
		// before skip on supported hosts; no skip/count ambiguity can widen
		// this view or silently turn a middle/end observation into zero bytes.
		view, err := json.Marshal(map[string]any{
			"driver": "raw", "file": json.RawMessage(graph[len("json:"):]),
			"offset": offset, "size": 4096, "read-only": true,
		})
		if err != nil {
			return nil, err
		}
		if _, err := encryptedHostOutput(ctx, v.dir, time.Minute, "qemu-img", "dd", "-O", "raw", "if=json:"+string(view), "of="+output, "bs=4096", "count=1"); err != nil {
			return nil, fmt.Errorf("read stopped disk sample: %w", err)
		}
		stat, err := os.Lstat(output)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() != 4096 {
			return nil, errors.New("stopped disk sample did not contain exactly 4096 bytes")
		}
		data, err := os.ReadFile(output)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		result.Samples = append(result.Samples, StoppedDiskSample{Offset: offset, Length: 4096, SHA256: hex.EncodeToString(digest[:])})
	}
	return result, nil
}

func stoppedDiskSampleOffsets(size int64) ([3]int64, error) {
	if size < 3*4096 || size > 64<<30 || size%512 != 0 {
		return [3]int64{}, errors.New("stopped disk size is outside supported sector-aligned bounds")
	}
	return [3]int64{0, ((size/2 - 2048) / 512) * 512, size - 4096}, nil
}

func stoppedDiskGraph(overlay, base *os.File) (string, error) {
	for _, file := range []*os.File{overlay, base} {
		stat, err := file.Stat()
		if err != nil || !stat.Mode().IsRegular() {
			return "", errors.New("stopped disk graph requires regular owned files")
		}
	}
	backing, err := encryptedQCOWBacking(overlay)
	if err != nil || backing != "/proc/self/fd/3" {
		return "", fmt.Errorf("unexpected configured overlay backing: %w", errors.Join(err, errors.New("expected pinned cloud base")))
	}
	backing, err = encryptedQCOWBacking(base)
	if err != nil || backing != "" {
		return "", fmt.Errorf("invalid pinned standalone base: %w", errors.Join(err, errors.New("base must have no backing")))
	}
	fileNode := func(file *os.File) map[string]any {
		return map[string]any{"driver": "file", "filename": fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd()), "read-only": true}
	}
	// Override the overlay's process-relative metadata with retained capabilities.
	// An explicit null backing on the base prevents any implicit image traversal.
	graph := map[string]any{"driver": "qcow2", "file": fileNode(overlay), "read-only": true,
		"backing": map[string]any{"driver": "qcow2", "file": fileNode(base), "read-only": true, "backing": nil}}
	encoded, err := json.Marshal(graph)
	if err != nil {
		return "", err
	}
	return "json:" + string(encoded), nil
}
