// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"lindm/internal/devlab/webauthnlab"
)

// Private lab credential state, not product configuration. Each account has one
// writer: a controller account stays here; an exported lane account lives there.
type persistentAccount struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Password     []byte `json:"password"`
	CredentialID []byte `json:"credential_id"`
	PrivateKey   []byte `json:"private_key"`
	Counter      uint32 `json:"counter"`
}

func (a *localAccount) persist() error {
	if a.statePath == "" {
		return nil
	}
	id, key, err := a.authenticator.Export()
	if err != nil {
		return err
	}
	defer clear(key)
	defer clear(id)
	return writePersistentJSON(a.statePath, persistentAccount{ID: a.id, Username: a.username, Password: a.password, CredentialID: id, PrivateKey: key, Counter: a.counter})
}

func restorePersistentAccount(path string) (*localAccount, error) {
	var saved persistentAccount
	if err := readPersistentJSON(path, &saved); err != nil {
		return nil, err
	}
	defer clear(saved.Password)
	defer clear(saved.PrivateKey)
	defer clear(saved.CredentialID)
	id, err := uuid.Parse(saved.ID)
	if err != nil || id == uuid.Nil || saved.Username == "" || len(saved.Password) == 0 || saved.Counter == 0 {
		return nil, errors.New("invalid persistent local account")
	}
	authenticator, err := webauthnlab.Import("localhost", saved.CredentialID, saved.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &localAccount{id: id.String(), username: saved.Username, password: bytes.Clone(saved.Password), authenticator: authenticator, counter: saved.Counter, statePath: path}, nil
}

func (f *AuthorityFixture) persistLocalAccounts() error {
	for name, account := range map[string]*localAccount{"owner": f.local.owner, "approver": f.local.approver} {
		if account == nil {
			return fmt.Errorf("persistent fixture has no %s account", name)
		}
		account.mu.Lock()
		account.statePath = filepath.Join(f.directory, name+".json")
		err := account.persist()
		account.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *AuthorityFixture) restoreLocalAccounts() error {
	f.local = &localAuthority{}
	var err error
	f.local.owner, err = restorePersistentAccount(filepath.Join(f.directory, "owner.json"))
	if err != nil {
		return err
	}
	f.local.approver, err = restorePersistentAccount(filepath.Join(f.directory, "approver.json"))
	return err
}

func exportedAccountPath(directory, username string) string {
	digest := sha256.Sum256([]byte(username))
	return filepath.Join(directory, "lane-"+hex.EncodeToString(digest[:])+".json")
}

// ConnectPersistentAuthorityFixture restores lane-owned authentication counters
// and its independent approver on the VM host. Its Close never revokes accounts.
// stateDir must survive remote-run teardown, and only one lane may open it.
func ConnectPersistentAuthorityFixture(ctx context.Context, handle *ControlPlaneHandle, stateDir string) (_ *AuthorityFixture, resultErr error) {
	if handle == nil {
		return nil, errors.New("connect authority requires a control-plane handle")
	}
	defer handle.ClearCredentials()
	dir, lock, fresh, err := lockPersistentDirectory(stateDir, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lock.Close())
		}
	}()
	if fresh {
		if err := writePersistentJSON(filepath.Join(dir, "connected.json"), 1); err != nil {
			return nil, err
		}
	}
	if !fresh {
		owner, err := restorePersistentAccount(filepath.Join(dir, "owner.json"))
		if err != nil {
			return nil, err
		}
		defer (&localAuthority{owner: owner}).close()
		if owner.id != handle.AccountID || owner.username != handle.Username {
			return nil, errors.New("persistent lane account differs from controller")
		}
		handle.ClearCredentials()
		handle.Password = bytes.Clone(owner.password)
		handle.WebAuthnCredentialID, handle.WebAuthnPrivateKey, err = owner.authenticator.Export()
		if err != nil {
			return nil, err
		}
		handle.WebAuthnCounter = owner.counter
	}
	f, err := connectAuthorityFixture(ctx, handle, dir, fresh)
	if err != nil {
		return nil, err
	}
	f.stateLock = lock
	f.Resumed = !fresh
	return f, nil
}

func (f *AuthorityFixture) persistedExport(username string) (*ControlPlaneHandle, error) {
	var handle ControlPlaneHandle
	err := readPersistentJSON(exportedAccountPath(f.directory, username), &handle)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		handle.ClearCredentials()
		return nil, err
	}
	if handle.Username != username || handle.DatabaseName != f.DatabaseName || handle.ConsoleOrigin != f.ConsoleOrigin || handle.DeviceOrigin != f.DeviceOrigin {
		handle.ClearCredentials()
		return nil, errors.New("persistent exported account identity mismatch")
	}
	return &handle, nil
}

// DestroyPersistentAuthorityFixture removes only the remote lane's credentials.
// It refuses live connections; it never owns or drops the controller database.
func DestroyPersistentAuthorityFixture(stateDir string) (resultErr error) {
	dir, lock, _, err := lockPersistentDirectory(stateDir, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	var version int
	if err := readPersistentJSON(filepath.Join(dir, "connected.json"), &version); err != nil {
		return err
	}
	if version != 1 {
		return errors.New("unsupported persistent connected authority state")
	}
	return os.RemoveAll(dir)
}
