// SPDX-License-Identifier: Apache-2.0

package desktop

import (
	"encoding/json"
	"errors"
	"sync"
)

// DisplayFrame identifies the first emitted RTP timestamp after the session
// timeline mapping for a selected source. Zero is a valid wrapped timestamp.
// The browser reconciles this marker with the report and presented RTP metadata;
// neither receiving a marker nor receiving a report proves frame presentation.
type DisplayFrame struct {
	Display      string `json:"display"`
	Generation   uint32 `json:"generation"`
	RTPTimestamp uint32 `json:"rtpTimestamp"`
}

// displayFrames serializes channel-open, source changes, first frame publication
// and shutdown. Only metadata is retained; no capture or input content is cached.
// send is the reliable ordered lindm-input channel's bounded SendText operation.
type displayFrames struct {
	mu         sync.Mutex
	display    string
	generation uint32
	marker     string
	send       func(string) error
	closed     bool
}

func (f *displayFrames) begin(display string, generation uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errSessionEnded
	}
	if display == "" || len(display) > 64 || generation == 0 {
		return errors.New("display_frame_invalid_source")
	}
	if display == f.display && generation == f.generation {
		return nil
	}
	if generation <= f.generation {
		return errors.New("display_frame_stale_generation")
	}
	f.display, f.generation, f.marker = display, generation, ""
	return nil
}

func (f *displayFrames) publish(frame DisplayFrame) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errSessionEnded
	}
	if frame.Generation == 0 {
		return errors.New("display_frame_invalid_source")
	}
	if frame.Display != f.display || frame.Generation != f.generation {
		return nil
	}
	// Repeated packets or replayed publications cannot replace the first marker.
	if f.marker != "" {
		return nil
	}
	encoded, err := json.Marshal(struct {
		Type string `json:"t"`
		DisplayFrame
	}{Type: "display-frame", DisplayFrame: frame})
	if err != nil {
		return err
	}
	if len(encoded) > maxInputMessageBytes {
		return errors.New("display_frame_message_too_large")
	}
	f.marker = string(encoded)
	if f.send != nil {
		return f.send(f.marker)
	}
	return nil
}

func (f *displayFrames) open(send func(string) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.send = send
	if f.marker != "" {
		return send(f.marker)
	}
	return nil
}

func (f *displayFrames) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed, f.marker, f.send = true, "", nil
}
