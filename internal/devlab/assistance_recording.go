// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	configv1 "lindm/gen/lindm/config/v1"
)

// assistanceRecordingKey is the owned server's recording key file name. A
// persistent fixture keeps it so retained recordings remain retrievable.
const assistanceRecordingKey = "assistance-recording.key"

// AssistanceRecordingCustody returns recording custody for the owned server,
// creating its owner-only 32-byte key beside the configuration once.
func (f *AuthorityFixture) AssistanceRecordingCustody(maxStorageBytes uint64) (*configv1.AssistanceRecordingConfig, error) {
	if f.closed || f.local == nil {
		return nil, errors.New("assistance recording requires an open local authority fixture")
	}
	path := filepath.Join(f.directory, assistanceRecordingKey)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		defer clear(seed)
		if err := writePersistentFile(path, seed); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return &configv1.AssistanceRecordingConfig{KeyFile: path, MaxStorageBytes: maxStorageBytes}, nil
}

// AssistanceRecordingAtRest is a read-only observation of one recording's
// stored ciphertext. It never returns segment bytes.
type AssistanceRecordingAtRest struct {
	Segments int   `json:"segments"`
	Bytes    int64 `json:"bytes"`
	// PlaintextMarkers counts stored segments that start with the WebM EBML
	// header or contain the VP8 codec identifier; sealed segments do not.
	PlaintextMarkers int `json:"plaintext_markers"`
	// KeyRetained is false once deletion or retention destroyed the key.
	KeyRetained bool `json:"encapsulated_key_retained"`
}

// InspectAssistanceRecording reads the owned database through a read-only
// administration connection, never through product authority.
func (f *AuthorityFixture) InspectAssistanceRecording(ctx context.Context, recordingID string) (_ AssistanceRecordingAtRest, resultErr error) {
	var observed AssistanceRecordingAtRest
	id, err := uuid.Parse(recordingID)
	if err != nil {
		return observed, errors.New("invalid recording identifier")
	}
	ctx, cancel := context.WithTimeout(ctx, databaseProfileTimeout)
	defer cancel()
	conn, err := f.profileConnection(ctx, true)
	if err != nil {
		return observed, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	if err := conn.QueryRow(ctx, `SELECT encapsulated_key IS NOT NULL FROM assistance_recordings WHERE id=$1`, id).Scan(&observed.KeyRetained); err != nil {
		return observed, profileError("read recording", err)
	}
	rows, err := conn.Query(ctx, `SELECT ciphertext FROM assistance_recording_segments WHERE recording_id=$1 ORDER BY sequence`, id)
	if err != nil {
		return observed, profileError("read recording segments", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ciphertext []byte
		if err := rows.Scan(&ciphertext); err != nil {
			return observed, profileError("read recording segment", err)
		}
		observed.Segments++
		observed.Bytes += int64(len(ciphertext))
		if bytes.HasPrefix(ciphertext, []byte{0x1A, 0x45, 0xDF, 0xA3}) || bytes.Contains(ciphertext, []byte("V_VP8")) {
			observed.PlaintextMarkers++
		}
		clear(ciphertext)
	}
	return observed, profileError("read recording segments", rows.Err())
}

// ExpireAssistanceRecording moves one finalized recording's retention
// deadline to now. It is the lab's clock acceleration for the server's own
// retention job, which still performs and audits the deletion.
func (f *AuthorityFixture) ExpireAssistanceRecording(ctx context.Context, recordingID string) (resultErr error) {
	id, err := uuid.Parse(recordingID)
	if err != nil {
		return errors.New("invalid recording identifier")
	}
	ctx, cancel := context.WithTimeout(ctx, databaseProfileTimeout)
	defer cancel()
	conn, err := f.profileConnection(ctx, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProfileConnection(conn)) }()
	tag, err := conn.Exec(ctx, `UPDATE assistance_recordings SET retain_until = now() WHERE id=$1 AND state IN (3, 4)`, id)
	if err != nil {
		return profileError("expire recording retention", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("recording is not a finalized retained archive")
	}
	return nil
}
