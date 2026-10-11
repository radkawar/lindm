//go:build linux

// Package measuredtpm is the root executor's TPM side of measured Boot Loader
// Spec recovery: it reads the firmware TCG event log, creates the restricted
// recovery attestation key under the owner-hierarchy storage key and quotes
// PCRs 4, 7, 8 and 9 (SHA-256 bank) with that key.
//
// It talks only to the kernel resource manager /dev/tpmrm0, every operation
// needs a context deadline, and no caller supplies a device path, handle, PCR
// selection or key template. The key never persists in the TPM: only its
// TPM-wrapped blobs leave this package, and every handle is flushed. Nonempty
// owner or storage-key authorization is unsupported. Admission policy (event
// log replay, GRUB sequence, Secure Boot) belongs to internal/measuredboot;
// this package only self-checks its own outputs with that package.
package measuredtpm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/sys/unix"

	"lindm/internal/measuredboot"
)

// EventLogPath is the kernel's export of the firmware TCG event log.
const EventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

const (
	resourceManagerPath = "/dev/tpmrm0"
	maxTPMMessage       = 65536
	maxPrivateBytes     = 1024
	qualifyingDataBytes = 32
	maxPCRBanks         = 16
)

var (
	errUnavailable      = errors.New("measuredtpm: tpm_unavailable")
	errDeadline         = errors.New("measuredtpm: deadline_required")
	errMessageSize      = errors.New("measuredtpm: tpm_message_too_large")
	errEventLogFile     = errors.New("measuredtpm: event_log_file_invalid")
	errEventLogTooLarge = errors.New("measuredtpm: event_log_too_large")
	errPCRBank          = errors.New("measuredtpm: sha256_pcr_bank_unavailable")
	errPrivate          = errors.New("measuredtpm: attestation_key_private_invalid")
	errQualifyingData   = errors.New("measuredtpm: qualifying_data_invalid")
	errQuote            = errors.New("measuredtpm: quote_invalid")
)

// ReadEventLog returns the current boot's raw TCG event log, at most
// measuredboot.MaxEventLogBytes, from the securityfs file EventLogPath.
func ReadEventLog() (data []byte, err error) {
	fd, err := unix.Open(EventLogPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	file := os.NewFile(uintptr(fd), EventLogPath)
	defer func() { err = errors.Join(err, file.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat event log: %w", err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, fmt.Errorf("statfs event log: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || fs.Type != unix.SECURITYFS_MAGIC {
		return nil, errEventLogFile
	}
	data, err = io.ReadAll(io.LimitReader(file, measuredboot.MaxEventLogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read event log: %w", err)
	}
	if len(data) > measuredboot.MaxEventLogBytes {
		return nil, errEventLogTooLarge
	}
	return data, nil
}

// Available reports whether measured recovery attestation can work on this
// boot: the event log is readable and crypto-agile with a SHA-256 bank, and
// the TPM resource manager is a usable character device whose SHA-256 PCR
// bank allocates PCRs 4, 7, 8 and 9. It does not judge the GRUB boot sequence.
func Available(ctx context.Context) error {
	data, err := ReadEventLog()
	if err != nil {
		return err
	}
	if _, err := measuredboot.ParseEventLog(data); err != nil {
		return fmt.Errorf("parse event log: %w", err)
	}
	return withTPM(ctx, checkPCRBank)
}

func checkPCRBank(t transport.TPM) error {
	// The reference TPM returns at most PropertyCount banks.
	response, err := (tpm2.GetCapability{Capability: tpm2.TPMCapPCRs, PropertyCount: maxPCRBanks}).Execute(t)
	if err != nil {
		return fmt.Errorf("get PCR allocation: %w", err)
	}
	allocation, err := response.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return fmt.Errorf("get PCR allocation: %w", err)
	}
	for _, bank := range allocation.PCRSelections {
		if bank.Hash == tpm2.TPMAlgSHA256 && selects(bank.PCRSelect, measuredboot.QuotePCRs[:]) {
			return nil
		}
	}
	return errPCRBank
}

func selects(bitmap []byte, pcrs []int) bool {
	for _, pcr := range pcrs {
		if pcr/8 >= len(bitmap) || bitmap[pcr/8]&(1<<(pcr%8)) == 0 {
			return false
		}
	}
	return true
}

// CreateAttestationKey creates a measuredboot.AttestationKeyTemplate key under
// the owner-hierarchy ECC storage key and returns the marshaled TPMT_PUBLIC
// and TPM2B_PRIVATE blob. The key is not loaded or persisted.
func CreateAttestationKey(ctx context.Context) (public, private []byte, err error) {
	err = withTPM(ctx, func(t transport.TPM) error {
		public, private, err = createAttestationKey(t)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return public, private, nil
}

func createAttestationKey(t transport.TPM) (public, private []byte, err error) {
	srk, err := createSRK(t)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, flush(t, srk.ObjectHandle)) }()
	created, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(measuredboot.AttestationKeyTemplate()),
	}).Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("create attestation key: %w", err)
	}
	public = bytes.Clone(created.OutPublic.Bytes())
	private = tpm2.Marshal(created.OutPrivate)
	if len(private) > maxPrivateBytes {
		return nil, nil, errPrivate
	}
	if _, err := measuredboot.ValidateAttestationKey(public); err != nil {
		return nil, nil, fmt.Errorf("validate created attestation key: %w", err)
	}
	return public, private, nil
}

// Quote loads the attestation key blobs under the owner-hierarchy storage key
// and quotes the SHA-256 bank of measuredboot.QuotePCRs with qualifyingData.
// It returns the TPMS_ATTEST bytes exactly as signed and the marshaled
// TPMT_SIGNATURE after checking both against public.
func Quote(ctx context.Context, public, private, qualifyingData []byte) (quote, signature []byte, err error) {
	if len(qualifyingData) != qualifyingDataBytes {
		return nil, nil, errQualifyingData
	}
	if _, err := measuredboot.ValidateAttestationKey(public); err != nil {
		return nil, nil, fmt.Errorf("validate attestation key: %w", err)
	}
	if len(private) > maxPrivateBytes {
		return nil, nil, errPrivate
	}
	privateBlob, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](private)
	if err != nil || !bytes.Equal(tpm2.Marshal(*privateBlob), private) {
		return nil, nil, errors.Join(errPrivate, err)
	}
	err = withTPM(ctx, func(t transport.TPM) error {
		quote, signature, err = quotePCRs(t, public, *privateBlob, qualifyingData)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return quote, signature, nil
}

func quotePCRs(t transport.TPM, public []byte, private tpm2.TPM2BPrivate, qualifyingData []byte) (quote, signature []byte, err error) {
	srk, err := createSRK(t)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, flush(t, srk.ObjectHandle)) }()
	loaded, err := (tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    private,
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](public),
	}).Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("load attestation key: %w", err)
	}
	defer func() { err = errors.Join(err, flush(t, loaded.ObjectHandle)) }()
	quoted, err := (tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		PCRSelect: quoteSelection(),
	}).Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("quote PCRs: %w", err)
	}
	quote = bytes.Clone(quoted.Quoted.Bytes())
	signature = tpm2.Marshal(quoted.Signature)
	if err := checkQuote(public, quote, signature, qualifyingData); err != nil {
		return nil, nil, err
	}
	return quote, signature, nil
}

// checkQuote verifies the signature and that the TPM quoted the requested
// qualifying data and PCR selection. PCR values are the verifier's concern.
func checkQuote(public, quote, signature, qualifyingData []byte) error {
	if err := measuredboot.VerifyQuoteSignature(public, quote, signature); err != nil {
		return fmt.Errorf("verify quote signature: %w", err)
	}
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote)
	if err != nil || attest.Type != tpm2.TPMSTAttestQuote || !bytes.Equal(attest.ExtraData.Buffer, qualifyingData) {
		return errors.Join(errQuote, err)
	}
	info, err := attest.Attested.Quote()
	if err != nil || !bytes.Equal(tpm2.Marshal(info.PCRSelect), tpm2.Marshal(quoteSelection())) {
		return errors.Join(errQuote, err)
	}
	return nil
}

// quoteSelection is the single SHA-256 selection of measuredboot.QuotePCRs
// with a 3-octet (PCR 0-23) select bitmap.
func quoteSelection() tpm2.TPMLPCRSelection {
	bitmap := make([]byte, 3)
	for _, pcr := range measuredboot.QuotePCRs {
		bitmap[pcr/8] |= 1 << (pcr % 8)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap}}}
}

func createSRK(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	response, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("create storage key: %w", err)
	}
	return response, nil
}

func flush(t transport.TPM, handle tpm2.TPMHandle) error {
	if _, err := (tpm2.FlushContext{FlushHandle: handle}).Execute(t); err != nil {
		return fmt.Errorf("flush TPM handle: %w", err)
	}
	return nil
}

type boundedTPM struct {
	ctx   context.Context
	inner transport.TPM
}

func (t boundedTPM) Send(input []byte) ([]byte, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) > maxTPMMessage {
		return nil, errMessageSize
	}
	result, err := t.inner.Send(input)
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}
	if len(result) > maxTPMMessage {
		return nil, errMessageSize
	}
	return result, err
}

// withTPM runs operation against the kernel TPM resource manager. The context
// must carry a deadline, which bounds every TPM read and write; cancellation
// closes the device.
func withTPM(ctx context.Context, operation func(transport.TPM) error) (err error) {
	if os.Geteuid() != 0 {
		return errUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errDeadline
	}
	fd, err := unix.Open(resourceManagerPath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Join(errUnavailable, fmt.Errorf("open TPM resource manager: %w", err))
	}
	file := os.NewFile(uintptr(fd), resourceManagerPath)
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
		return fmt.Errorf("stat TPM resource manager: %w", err)
	}
	// tpm2-tss udev rules make the node tss:tss 0660, so ownership is not
	// required to be root; a world-writable node is refused.
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || st.Mode&0o002 != 0 {
		return errUnavailable
	}
	// Nonblocking TPM character-device I/O is pollable; refuse drivers that
	// cannot honor the deadline rather than leave a blocked kernel call running.
	if err := file.SetDeadline(deadline); err != nil {
		return errors.Join(errUnavailable, err)
	}
	return operation(boundedTPM{ctx: ctx, inner: transport.FromReadWriter(file)})
}
