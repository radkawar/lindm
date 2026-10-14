// SPDX-License-Identifier: Apache-2.0

//go:build linux

package measuredtpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"lindm/internal/measuredboot"
)

func TestQuoteSelection(t *testing.T) {
	// TPML_PCR_SELECTION: count 1, TPM_ALG_SHA256, sizeofSelect 3, PCRs 4,7 | 8,9.
	want := []byte{0, 0, 0, 1, 0x00, 0x0b, 3, 0x90, 0x03, 0x00}
	if got := tpm2.Marshal(quoteSelection()); !bytes.Equal(got, want) {
		t.Fatalf("quote selection = %x, want %x", got, want)
	}
}

func TestSelects(t *testing.T) {
	if !selects([]byte{0x90, 0x03, 0x00}, measuredboot.QuotePCRs[:]) || !selects([]byte{0xff, 0xff, 0xff}, measuredboot.QuotePCRs[:]) {
		t.Fatal("full allocation not accepted")
	}
	for _, bitmap := range [][]byte{nil, {0x90}, {0x80, 0x03, 0}, {0x90, 0x01, 0}} {
		if selects(bitmap, measuredboot.QuotePCRs[:]) {
			t.Fatalf("selects(%x) = true", bitmap)
		}
	}
}

func TestQuoteRejectsInputsBeforeTPM(t *testing.T) {
	ctx := t.Context()
	if _, _, err := Quote(ctx, nil, nil, make([]byte, 31)); !errors.Is(err, errQualifyingData) {
		t.Fatalf("short qualifying data error = %v", err)
	}
	if _, _, err := Quote(ctx, []byte{0}, nil, make([]byte, 32)); err == nil {
		t.Fatal("Quote accepted an invalid attestation key public area")
	}
	if _, _, err := Quote(ctx, newPublic(t), []byte{0, 4, 1}, make([]byte, 32)); !errors.Is(err, errPrivate) {
		t.Fatalf("truncated private error = %v", err)
	}
}

// newPublic returns a valid attestation key public area with a software point.
func newPublic(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	public := measuredboot.AttestationKeyTemplate()
	public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: encoded[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: encoded[33:]},
	})
	return tpm2.Marshal(public)
}

func TestWithTPMRequiresDeadline(t *testing.T) {
	requireTPM(t)
	if err := withTPM(t.Context(), checkPCRBank); !errors.Is(err, errDeadline) {
		t.Fatalf("withTPM without deadline error = %v", err)
	}
}

func requireTPM(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat(resourceManagerPath); err != nil {
		t.Skipf("requires %s: %v", resourceManagerPath, err)
	}
}

func TestCreateAttestationKeyAndQuote(t *testing.T) {
	requireTPM(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	public, private, err := CreateAttestationKey(ctx)
	if err != nil {
		t.Fatalf("CreateAttestationKey: %v", err)
	}
	if _, err := measuredboot.ValidateAttestationKey(public); err != nil {
		t.Fatalf("ValidateAttestationKey: %v", err)
	}
	qualifyingData := measuredboot.QualifyingData([]byte("receipt"), []byte("challenge"))
	quote, signature, err := Quote(ctx, public, private, qualifyingData)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if err := measuredboot.VerifyQuoteSignature(public, quote, signature); err != nil {
		t.Fatalf("VerifyQuoteSignature: %v", err)
	}
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote)
	if err != nil || !bytes.Equal(attest.ExtraData.Buffer, qualifyingData) {
		t.Fatalf("quote = %+v, %v", attest, err)
	}
	other := measuredboot.QualifyingData([]byte("other"), []byte("challenge"))
	if err := checkQuote(public, quote, signature, other); !errors.Is(err, errQuote) {
		t.Fatalf("checkQuote with other qualifying data error = %v", err)
	}
}

func TestAvailableAndEventLog(t *testing.T) {
	requireTPM(t)
	if _, err := os.Stat(EventLogPath); err != nil {
		t.Skipf("requires %s: %v", EventLogPath, err)
	}
	data, err := ReadEventLog()
	if err != nil {
		t.Fatalf("ReadEventLog: %v", err)
	}
	if _, err := measuredboot.ParseEventLog(data); err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := Available(ctx); err != nil {
		t.Fatalf("Available: %v", err)
	}
}
