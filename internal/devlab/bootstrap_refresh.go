// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

// refreshDevelopmentBootstrap is called only after current-schema admission
// fails, while the caller holds the fixture lock. The landing gate additionally
// holds the host integration lock. Only the missing console pin is repairable:
// authenticate the original quorum, retain every other signed field and key,
// then admit the replacement with the unmodified production verifier.
func refreshDevelopmentBootstrap(ctx context.Context, authority *trust.Authority, dir string, rootJSON, encoded []byte) (*trust.Bootstrap, []byte, error) {
	envelope, bundle, err := developmentBootstrapEnvelope(encoded)
	if err != nil {
		return nil, nil, err
	}
	if len(bundle.GetConsoleCaPem()) != 0 {
		return nil, nil, errors.New("development bootstrap already has console trust; refusing schema repair")
	}
	if err := authenticateDevelopmentBootstrap(ctx, rootJSON, envelope); err != nil {
		return nil, nil, err
	}
	files, err := readDevelopmentTrustFiles(dir)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		for name, content := range files {
			if filepath.Ext(name) == ".pem" {
				clear(content)
			}
		}
	}()
	if !bytes.Equal(rootJSON, files["execution-root.json"]) || !bytes.Equal(encoded, files["bootstrap.dsse.json"]) {
		return nil, nil, errors.New("development trust changed during schema repair")
	}
	fixture := filepath.Dir(dir)
	transport, err := readOwned(filepath.Join(fixture, "transport-ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	device, err := readOwned(filepath.Join(fixture, "device-ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	if bundle.GetEnrollmentOrigin() != consoleOrigin || bundle.GetDeviceOrigin() != "https://localhost:18445" || !bytes.Equal(bundle.GetTransportCaPem(), transport) || !bytes.Equal(bundle.GetDeviceCaPem(), device) {
		return nil, nil, errors.New("development bootstrap does not bind the existing HTTPS issuers and origins")
	}
	bundle.ConsoleCaPem = transport
	root := new(agentv1.ExecutionRoot)
	if err := protojson.Unmarshal(rootJSON, root); err != nil {
		return nil, nil, err
	}
	keys := make([]ed25519.PrivateKey, 0, len(root.GetKeys()))
	for i := range root.GetKeys() {
		key, err := developmentPrivateKey(files[fmt.Sprintf("execution-key-%d.pem", i)])
		if err != nil {
			return nil, nil, err
		}
		defer clear(key)
		keys = append(keys, key)
	}
	replacement, err := authority.Sign(ctx, bundle, keys[:root.GetThreshold()]...)
	if err != nil {
		return nil, nil, err
	}
	verified, err := authority.VerifyBootstrap(ctx, rootJSON, replacement, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := verifyDevelopmentTrustKeys(files, verified); err != nil {
		return nil, nil, err
	}
	if err := replaceDevelopmentBootstrap(dir, replacement); err != nil {
		return nil, nil, err
	}
	return verified, replacement, nil
}

func developmentBootstrapEnvelope(encoded []byte) (*dsse.Envelope, *agentv1.BootstrapBundle, error) {
	if len(encoded) == 0 || len(encoded) > maxFixtureFile {
		return nil, nil, errors.New("invalid development bootstrap envelope size")
	}
	envelope := new(dsse.Envelope)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(envelope); err != nil {
		return nil, nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("trailing development bootstrap envelope data")
	}
	if envelope.PayloadType != trust.BootstrapType || len(envelope.Signatures) == 0 || len(envelope.Signatures) > 32 {
		return nil, nil, errors.New("invalid development bootstrap domain or signature count")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, nil, err
	}
	bundle := new(agentv1.BootstrapBundle)
	if err := proto.Unmarshal(payload, bundle); err != nil {
		return nil, nil, err
	}
	if err := protodata.ValidateClosed(bundle.ProtoReflect()); err != nil {
		return nil, nil, err
	}
	return envelope, bundle, nil
}

func authenticateDevelopmentBootstrap(ctx context.Context, encoded []byte, envelope *dsse.Envelope) error {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return errors.New("invalid development execution root size")
	}
	root := new(agentv1.ExecutionRoot)
	if err := protojson.Unmarshal(encoded, root); err != nil {
		return err
	}
	if root.GetThreshold() == 0 || len(root.GetKeys()) > 32 || int(root.GetThreshold()) > len(root.GetKeys()) {
		return errors.New("invalid development execution root quorum")
	}
	verifiers := make([]dsse.Verifier, 0, len(root.GetKeys()))
	for _, key := range root.GetKeys() {
		public := ed25519.PublicKey(key.GetPublicKey())
		id, err := trust.KeyID(public)
		if err != nil || id != key.GetKeyId() {
			return errors.New("development root key identity mismatch")
		}
		verifiers = append(verifiers, developmentBootstrapVerifier{public: public, id: id})
	}
	verifier, err := dsse.NewMultiEnvelopeVerifier(int(root.GetThreshold()), verifiers...)
	if err != nil {
		return err
	}
	if _, _, err := verifier.VerifyAndDecode(ctx, envelope); err != nil {
		return errors.New("original development bootstrap quorum verification failed")
	}
	return nil
}

type developmentBootstrapVerifier struct {
	public ed25519.PublicKey
	id     string
}

func (v developmentBootstrapVerifier) Public() crypto.PublicKey { return v.public }
func (v developmentBootstrapVerifier) KeyID() (string, error)   { return v.id, nil }
func (v developmentBootstrapVerifier) Verify(ctx context.Context, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !ed25519.Verify(v.public, message, signature) {
		return errors.New("invalid original development bootstrap signature")
	}
	return nil
}

func replaceDevelopmentBootstrap(dir string, encoded []byte) (err error) {
	file, err := os.CreateTemp(dir, ".bootstrap-schema-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() {
		removeErr := os.Remove(name)
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	_, err = file.Write(encoded)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, "bootstrap.dsse.json")); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
