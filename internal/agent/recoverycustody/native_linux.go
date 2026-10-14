// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recoverycustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/sys/unix"
)

// The reserved owner-hierarchy handles are local implementation constants. No
// caller supplies a path, index, auth hierarchy, TPM command or replacement flag.
// Nonempty owner authorization is unsupported; failures never fall back to an
// empty policy or overwrite an occupied object/index.
type nativeTPM struct{}

type boundedTPM struct {
	ctx   context.Context
	inner transport.TPM
}

func (t boundedTPM) Send(input []byte) ([]byte, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) > 65536 {
		return nil, ErrUnsupported
	}
	result, err := t.inner.Send(input)
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}
	if len(result) > 65536 {
		return nil, ErrUnsupported
	}
	return result, err
}

func withTPM(ctx context.Context, operation func(transport.TPM) error) (err error) {
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Open("/dev/tpmrm0", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open qualified TPM resource manager: %w", err)
	}
	file := os.NewFile(uintptr(fd), "tpm2-recovery-resource-manager")
	var once sync.Once
	var closeErr error
	closeFile := func() { once.Do(func() { closeErr = file.Close() }) }
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { closeFile(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
		closeFile()
		err = errors.Join(err, closeErr)
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Uid != 0 || st.Mode&0002 != 0 {
		return ErrUnsupported
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrUnsupported
	}
	// Nonblocking TPM character-device I/O is pollable on qualified Linux
	// kernels. Refuse drivers without deadlines rather than leave a blocked
	// kernel read/write running after the authority context has expired.
	if err := file.SetDeadline(deadline); err != nil {
		return errors.Join(ErrUnsupported, err)
	}
	return operation(boundedTPM{ctx: ctx, inner: transport.FromReadWriter(file)})
}

func secureBootEnabled() error {
	const prefix = "/sys/firmware/efi/efivars/"
	const suffix = "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	for name, wanted := range map[string]byte{"SecureBoot": 1, "SetupMode": 0} {
		fd, err := unix.Open(prefix+name+suffix, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("%w: secure_boot_variable: %v", ErrUnsupported, err)
		}
		file := os.NewFile(uintptr(fd), name)
		data, readErr := io.ReadAll(io.LimitReader(file, 6))
		err = errors.Join(readErr, file.Close())
		if err != nil || len(data) != 5 || data[4] != wanted {
			return errors.Join(ErrUnsupported, err)
		}
	}
	return nil
}

func pcrSelection() tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0x80, 0x08, 0}}}}
}

func readPCRs(t transport.TPM) ([]byte, []byte, error) {
	selection := pcrSelection()
	response, err := (tpm2.PCRRead{PCRSelectionIn: selection}).Execute(t)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(tpm2.Marshal(response.PCRSelectionOut), tpm2.Marshal(selection)) || len(response.PCRValues.Digests) != 2 || len(response.PCRValues.Digests[0].Buffer) != 32 || len(response.PCRValues.Digests[1].Buffer) != 32 {
		return nil, nil, ErrUnsupported
	}
	pcr7, pcr11 := response.PCRValues.Digests[0].Buffer, response.PCRValues.Digests[1].Buffer
	if bytes.Equal(pcr7, make([]byte, 32)) {
		return nil, nil, ErrUnsupported
	}
	return pcr7, pcr11, nil
}

func recoveryPolicy(pcr7, pcr11 []byte) ([]byte, error) {
	if len(pcr7) != 32 || len(pcr11) != 32 {
		return nil, ErrUnsupported
	}
	var values [64]byte
	copy(values[:32], pcr7)
	copy(values[32:], pcr11)
	digest := sha256.Sum256(values[:])
	policy, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyPCR{Pcrs: pcrSelection(), PcrDigest: tpm2.TPM2BDigest{Buffer: digest[:]}}).Update(policy); err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyCommandCode{Code: tpm2.TPMCCUnseal}).Update(policy); err != nil {
		return nil, err
	}
	return policy.Hash().Digest, nil
}

func vacant(t transport.TPM, handle uint32) error {
	response, err := (tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: handle, PropertyCount: 1}).Execute(t)
	if err != nil {
		return err
	}
	handles, err := response.CapabilityData.Data.Handles()
	if err != nil {
		return err
	}
	if len(handles.Handle) > 1 {
		return ErrUnsupported
	}
	if len(handles.Handle) == 1 && uint32(handles.Handle[0]) == handle {
		return ErrOccupied
	}
	return nil
}

func reservedVacant(t transport.TPM) error {
	for _, handle := range []uint32{PersistentHandle, CounterIndex, CheckpointIndex} {
		if err := vacant(t, handle); err != nil {
			return err
		}
	}
	return nil
}

func (nativeTPM) check(ctx context.Context) ([]byte, error) {
	if err := secureBootEnabled(); err != nil {
		return nil, err
	}
	var pcr7 []byte
	err := withTPM(ctx, func(t transport.TPM) error {
		if err := reservedVacant(t); err != nil {
			return err
		}
		var err error
		pcr7, _, err = readPCRs(t)
		return err
	})
	return pcr7, err
}

func sealedTemplate(policy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, AdminWithPolicy: true, NoDA: true},
		AuthPolicy:       tpm2.TPM2BDigest{Buffer: policy},
	}
}

func nvTemplate(index uint32) tpm2.TPMSNVPublic {
	attributes := tpm2.TPMANV{AuthWrite: true, AuthRead: true, NoDA: true}
	size := uint16(nvBytes)
	if index == CounterIndex {
		attributes.NT = tpm2.TPMNTCounter
		size = 8
	} else {
		attributes.NT = tpm2.TPMNTOrdinary
		attributes.WriteAll = true
	}
	return tpm2.TPMSNVPublic{NVIndex: tpm2.TPMHandle(index), NameAlg: tpm2.TPMAlgSHA256, Attributes: attributes, DataSize: size}
}

func validateNVPublic(public *tpm2.TPMSNVPublic, index uint32) error {
	if index != CounterIndex && index != CheckpointIndex {
		return ErrUnsupported
	}
	expected := nvTemplate(index)
	if public == nil || public.NVIndex != expected.NVIndex || public.NameAlg != expected.NameAlg || public.DataSize != expected.DataSize || len(public.AuthPolicy.Buffer) != 0 {
		return ErrUnknown
	}
	attributes := public.Attributes
	attributes.Written = false
	if !bytes.Equal(tpm2.Marshal(attributes), tpm2.Marshal(expected.Attributes)) {
		return ErrUnknown
	}
	return nil
}

func nvPublic(t transport.TPM, index uint32) (*tpm2.NVReadPublicResponse, error) {
	response, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}).Execute(t)
	if err != nil {
		return nil, err
	}
	public, err := response.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	if err := validateNVPublic(public, index); err != nil {
		return nil, err
	}
	name, err := tpm2.NVName(public)
	if err != nil || !bytes.Equal(name.Buffer, response.NVName.Buffer) {
		return nil, errors.Join(ErrUnknown, err)
	}
	return response, nil
}

func nvAuth(index uint32, name tpm2.TPM2BName, auth []byte) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: tpm2.TPMHandle(index), Name: name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 32, tpm2.Auth(auth))}
}

func nvRead(t transport.TPM, index uint32, auth []byte) ([]byte, error) {
	public, err := nvPublic(t, index)
	if err != nil {
		return nil, err
	}
	size := uint16(nvBytes)
	if index == CounterIndex {
		size = 8
	}
	response, err := (tpm2.NVRead{AuthHandle: nvAuth(index, public.NVName, auth), NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: public.NVName}, Size: size}).Execute(t)
	if err != nil {
		return nil, err
	}
	if len(response.Data.Buffer) != int(size) {
		return nil, ErrUnknown
	}
	return response.Data.Buffer, nil
}

func nvIncrement(t transport.TPM, auth []byte) (uint64, error) {
	public, err := nvPublic(t, CounterIndex)
	if err != nil {
		return 0, err
	}
	if _, err := (tpm2.NVIncrement{AuthHandle: nvAuth(CounterIndex, public.NVName, auth), NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(CounterIndex), Name: public.NVName}}).Execute(t); err != nil {
		return 0, err
	}
	data, err := nvRead(t, CounterIndex, auth)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

func nvWrite(t transport.TPM, auth, data []byte) error {
	if len(data) != nvBytes {
		return ErrUnsupported
	}
	public, err := nvPublic(t, CheckpointIndex)
	if err != nil {
		return err
	}
	_, err = (tpm2.NVWrite{AuthHandle: nvAuth(CheckpointIndex, public.NVName, auth), NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(CheckpointIndex), Name: public.NVName}, Data: tpm2.TPM2BMaxNVBuffer{Buffer: data}}).Execute(t)
	return err
}

func readObject(t transport.TPM) (*tpm2.ReadPublicResponse, *tpm2.TPMTPublic, error) {
	response, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(PersistentHandle)}).Execute(t)
	if err != nil {
		return nil, nil, err
	}
	public, err := response.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	expected := sealedTemplate(public.AuthPolicy.Buffer)
	if public.Type != expected.Type || public.NameAlg != expected.NameAlg || len(public.AuthPolicy.Buffer) != 32 || !bytes.Equal(tpm2.Marshal(public.ObjectAttributes), tpm2.Marshal(expected.ObjectAttributes)) || len(response.Name.Buffer) != 34 {
		return nil, nil, ErrUnknown
	}
	name, err := tpm2.ObjectName(public)
	if err != nil || !bytes.Equal(name.Buffer, response.Name.Buffer) {
		return nil, nil, errors.Join(ErrUnknown, err)
	}
	return response, public, nil
}

func readState(t transport.TPM, auth []byte) (nativeState, error) {
	object, public, err := readObject(t)
	if err != nil {
		return nativeState{}, err
	}
	counter, err := nvRead(t, CounterIndex, auth)
	if err != nil {
		return nativeState{}, err
	}
	data, err := nvRead(t, CheckpointIndex, auth)
	if err != nil {
		return nativeState{}, err
	}
	return nativeState{name: object.Name.Buffer, policy: public.AuthPolicy.Buffer, counter: binary.BigEndian.Uint64(counter), data: data}, nil
}

func createSRK(t transport.TPM) (*tpm2.CreatePrimaryResponse, *tpm2.TPMTPublic, error) {
	response, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(t)
	if err != nil {
		return nil, nil, err
	}
	public, err := response.OutPublic.Contents()
	if err != nil {
		_, flushErr := (tpm2.FlushContext{FlushHandle: response.ObjectHandle}).Execute(t)
		return nil, nil, errors.Join(err, flushErr)
	}
	return response, public, nil
}

func (nativeTPM) reserve(ctx context.Context, payload, policy, auth []byte, initial func([]byte, uint64) ([]byte, error)) (state nativeState, err error) {
	if len(payload) != 64 || len(policy) != 32 || len(auth) != 32 {
		return state, ErrUnsupported
	}
	err = withTPM(ctx, func(t transport.TPM) (err error) {
		if err := reservedVacant(t); err != nil {
			return err
		}
		srk, srkPublic, err := createSRK(t)
		if err != nil {
			return err
		}
		defer func() {
			_, flushErr := (tpm2.FlushContext{FlushHandle: srk.ObjectHandle}).Execute(t)
			err = errors.Join(err, flushErr)
		}()
		parent := tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 32, tpm2.Salted(srk.ObjectHandle, *srkPublic), tpm2.AESEncryption(128, tpm2.EncryptIn))}
		created, err := (tpm2.Create{ParentHandle: parent, InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: payload})}}, InPublic: tpm2.New2B(sealedTemplate(policy))}).Execute(t)
		if err != nil {
			return err
		}
		loaded, err := (tpm2.Load{ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)}, InPrivate: created.OutPrivate, InPublic: created.OutPublic}).Execute(t)
		if err != nil {
			return err
		}
		defer func() {
			_, flushErr := (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}).Execute(t)
			err = errors.Join(err, flushErr)
		}()
		if _, err := (tpm2.EvictControl{Auth: tpm2.TPMRHOwner, ObjectHandle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name}, PersistentHandle: tpm2.TPMHandle(PersistentHandle)}).Execute(t); err != nil {
			return err
		}
		// Never roll back this reservation by evicting/undefining TPM state. A
		// partially provisioned reservation blocks reuse and requires operator care.
		for _, index := range []uint32{CounterIndex, CheckpointIndex} {
			owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 32, tpm2.Salted(srk.ObjectHandle, *srkPublic), tpm2.AESEncryption(128, tpm2.EncryptIn))}
			if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, Auth: tpm2.TPM2BAuth{Buffer: auth}, PublicInfo: tpm2.New2B(nvTemplate(index))}).Execute(t); err != nil {
				return err
			}
		}
		counter, err := nvIncrement(t, auth)
		if err != nil || counter == 0 {
			return errors.Join(ErrUnknown, err)
		}
		data, err := initial(loaded.Name.Buffer, counter)
		if err != nil {
			return err
		}
		if err := nvWrite(t, auth, data); err != nil {
			return err
		}
		state, err = readState(t, auth)
		return err
	})
	return state, err
}

func (nativeTPM) read(ctx context.Context, auth []byte) (state nativeState, err error) {
	err = withTPM(ctx, func(t transport.TPM) error { var err error; state, err = readState(t, auth); return err })
	return state, err
}

func (nativeTPM) advance(ctx context.Context, auth []byte, expected uint64, next func(uint64) ([]byte, error)) (state nativeState, err error) {
	err = withTPM(ctx, func(t transport.TPM) error {
		prior, err := readState(t, auth)
		if err != nil {
			return err
		}
		if prior.counter != expected || expected == ^uint64(0) {
			return ErrUnknown
		}
		counter, err := nvIncrement(t, auth)
		if err != nil || counter != expected+1 {
			return errors.Join(ErrUnknown, err)
		}
		data, err := next(counter)
		if err != nil {
			return err
		}
		if err := nvWrite(t, auth, data); err != nil {
			return err
		}
		state, err = readState(t, auth)
		return err
	})
	return state, err
}

func (nativeTPM) open(ctx context.Context) (payload []byte, state nativeState, err error) {
	if err := lockProcessMemory(); err != nil {
		return nil, state, err
	}
	if err := secureBootEnabled(); err != nil {
		return nil, state, err
	}
	err = withTPM(ctx, func(t transport.TPM) (err error) {
		object, public, err := readObject(t)
		if err != nil {
			return err
		}
		pcr7, pcr11, err := readPCRs(t)
		if err != nil {
			return err
		}
		policy, err := recoveryPolicy(pcr7, pcr11)
		if err != nil || !bytes.Equal(policy, public.AuthPolicy.Buffer) {
			return errors.Join(ErrUnsupported, err)
		}
		srk, srkPublic, err := createSRK(t)
		if err != nil {
			return err
		}
		defer func() {
			_, flushErr := (tpm2.FlushContext{FlushHandle: srk.ObjectHandle}).Execute(t)
			err = errors.Join(err, flushErr)
		}()
		session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 32, tpm2.Salted(srk.ObjectHandle, *srkPublic), tpm2.AESEncryption(128, tpm2.EncryptOut))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, closeSession()) }()
		if _, err := (tpm2.PolicyPCR{PolicySession: session.Handle(), Pcrs: pcrSelection()}).Execute(t); err != nil {
			return err
		}
		if _, err := (tpm2.PolicyCommandCode{PolicySession: session.Handle(), Code: tpm2.TPMCCUnseal}).Execute(t); err != nil {
			return err
		}
		unsealed, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(PersistentHandle), Name: object.Name, Auth: session}}).Execute(t)
		if err != nil {
			return err
		}
		payload = unsealed.OutData.Buffer
		if len(payload) != 64 {
			clear(payload)
			payload = nil
			return ErrUnknown
		}
		state, err = readState(t, payload[32:])
		return err
	})
	if err != nil {
		clear(payload)
		payload = nil
	}
	return payload, state, err
}
