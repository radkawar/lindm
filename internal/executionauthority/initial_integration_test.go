// SPDX-License-Identifier: Apache-2.0

//go:build integration

package executionauthority

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestInitialDelegationCannotReplayOrRotateAfterAdmission(t *testing.T) {
	f := newFixture(t, 1)
	store := f.open(t)
	request := f.request(t, f.root, f.keys, 1, 0, false)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyInitial(f.ctx, tx, request, f.actor, "verified first-owner setup"); err != nil {
		t.Fatal(errors.Join(err, tx.Rollback(f.ctx)))
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, next := range []uint64{1, 2} {
		attempt := request
		if next > 1 {
			attempt = f.request(t, f.root, f.keys, next, 0, false)
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, admissionErr := store.ApplyInitial(f.ctx, tx, attempt, f.actor, "cannot reuse setup for rotation")
		if err := tx.Rollback(f.ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatal(err)
		}
		if !errors.Is(admissionErr, ErrRejected) {
			t.Fatalf("initial request version %d after admission: %v", next, admissionErr)
		}
	}
	// Ordinary quorum-authorized administrative admission remains available.
	if _, err := f.apply(t, store, f.request(t, f.root, f.keys, 2, 0, false), "authorized subsequent delegation"); err != nil {
		t.Fatal(err)
	}
}

func TestInitialDelegationSignatureAndTransactionRemainFailClosed(t *testing.T) {
	f := newFixture(t, 1)
	store := f.open(t)
	request := f.request(t, f.root, f.keys, 1, 0, false)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyInitial(f.ctx, tx, request, f.actor, "setup transaction that will abort"); err != nil {
		t.Fatal(errors.Join(err, tx.Rollback(f.ctx)))
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Get(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.DelegationEnvelope) != 0 {
		t.Fatal("aborted setup retained execution delegation")
	}
	invalid := f.request(t, f.root, []ed25519.PrivateKey{newKey(t)}, 1, 0, false)
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, admissionErr := store.ApplyInitial(f.ctx, tx, invalid, f.actor, "invalid setup signer")
	if err := tx.Rollback(f.ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	if !errors.Is(admissionErr, ErrRejected) {
		t.Fatalf("unsigned installation exception: %v", admissionErr)
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyInitial(f.ctx, tx, request, f.actor, "verified setup retry after rollback"); err != nil {
		t.Fatal(errors.Join(err, tx.Rollback(f.ctx)))
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
