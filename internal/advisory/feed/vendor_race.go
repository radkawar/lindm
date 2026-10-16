// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// Only mutable Red Hat JSON can reacquire a complete set after an integrity
// mismatch: one initial set and at most two additional independently verified
// sets, all inside the caller's unchanged acquisition limits and deadline.
const vendorCSAFSets = 3

type vendorRaceRefetchCounterKey struct{}

// WithVendorRaceRefetchCounter attributes additional consistent vendor sets to
// one actual source refresh. Parallel replacement tasks share this counter; a
// nil counter leaves ctx unchanged. HTTP retries use their separate counter.
func WithVendorRaceRefetchCounter(ctx context.Context, counter *atomic.Int64) context.Context {
	if counter == nil {
		return ctx
	}
	return context.WithValue(ctx, vendorRaceRefetchCounterKey{}, counter)
}

// VendorRaceRefetchCounter returns the refresh's set-refetch counter, or nil
// when the caller has not installed refresh accounting.
func VendorRaceRefetchCounter(ctx context.Context) *atomic.Int64 {
	counter, _ := ctx.Value(vendorRaceRefetchCounterKey{}).(*atomic.Int64)
	return counter
}

// Only this type permits a signature-triggered fresh set. The OpenPGP library's
// SignatureError also includes metadata/policy failures, so it is insufficient
// on its own to identify a cryptographic mismatch.
type vendorSignatureMismatch struct{ err error }

func (e *vendorSignatureMismatch) Error() string { return e.err.Error() }
func (e *vendorSignatureMismatch) Unwrap() error { return e.err }

// vendorCryptoMismatch classifies binary signatures after ordinary verification
// fails. Rehash only the failed staged file and invoke the cryptographic
// primitive, not the metadata-policy checker. Non-seekable inputs retain
// fail-closed, no-refetch behavior. This does not authenticate bytes: successful
// acquisition still requires the complete original verifier, including all
// signer/time/key policy, to pass.
func vendorCryptoMismatch(ctx context.Context, keys openpgp.EntityList, fingerprint string, payload io.Reader, sig *packet.Signature, now time.Time, config *packet.Config) (bool, error) {
	staged, ok := payload.(io.ReadSeeker)
	if !ok || sig.IssuerKeyId == nil || !sig.Hash.Available() {
		return false, nil
	}
	for _, signer := range keys.EntitiesById(*sig.IssuerKeyId) {
		if strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint)) != fingerprint {
			continue
		}
		key, valid := signer.SigningKeyById(sig.CreationTime, *sig.IssuerKeyId, config)
		if !valid {
			continue
		}
		if _, valid := signer.SigningKeyById(now, *sig.IssuerKeyId, config); !valid {
			continue
		}
		if _, err := staged.Seek(0, io.SeekStart); err != nil {
			return false, fmt.Errorf("feed: rewind failed signed CSAF: %w", err)
		}
		digest := sig.Hash.New()
		digest.Write(sig.Salt())
		if _, err := io.Copy(digest, contextFeedReader{ctx, staged}); err != nil {
			return false, fmt.Errorf("feed: read failed signed CSAF: %w", err)
		}
		var mismatch pgperrors.SignatureError
		return errors.As(key.PublicKey.VerifySignature(digest, sig), &mismatch), nil
	}
	return false, nil
}
