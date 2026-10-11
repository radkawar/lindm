// Package measuredboot verifies measured Boot Loader Spec recovery boots.
//
// A stock shim+GRUB chain boots a vendor-signed kernel with an unsigned lindm
// recovery initramfs. Secure Boot cannot verify that initramfs, so the server
// admits the recovery only after verifying a TPM2 quote over PCRs 4, 7, 8 and
// 9 (SHA-256 bank), replaying the supplied TCG PC Client event log against the
// quoted digest and checking that the final GRUB boot loaded exactly the
// approved kernel, kernel options and initramfs with Secure Boot enabled.
//
// The package is platform neutral and performs no I/O. It owns the closed
// recovery kernel-option grammar, the quote qualifying-data derivation, the
// attestation key template and the verification policy. It does not talk to a
// TPM (internal/agent/measuredtpm does), does not verify an endorsement-key
// chain and does not interpret firmware or GRUB events beyond what the policy
// names. Only digests are bound to the quoted PCR values: GRUB command text is
// accepted only when it hashes to its digest, Secure Boot variable data only
// when it hashes to its digest, and PCR 9 file paths are unauthenticated
// labels whose security rests on the measured file digests and kernel_cmdline.
package measuredboot

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// QuotePCRs are the SHA-256 PCRs quoted for a measured recovery boot, ascending.
var QuotePCRs = [...]int{4, 7, 8, 9}

// Domain separates measured-boot quote qualifying data from every other use of
// the receipt and challenge digests.
const Domain = "lindm.recovery.measured-boot.quote.v1"

// MaxEventLogBytes bounds a TCG event log accepted by ParseEventLog.
const MaxEventLogBytes = 262144

const (
	kernelOptionsPrefix = "rdinit=/init panic=10 quiet"
	actionOption        = " lindm.recovery.action="
	maxKernelOptions    = 256
)

// serialConsoles is the closed set of qualified recovery serial consoles. The
// empty console means no serial console options.
var serialConsoles = [...]string{"", "ttyS0,115200n8", "ttyAMA0,115200"}

var (
	errActionID      = errors.New("measuredboot: kernel_options_action_invalid")
	errSerialConsole = errors.New("measuredboot: kernel_options_console_invalid")
	errKernelOptions = errors.New("measuredboot: kernel_options_invalid")
)

// QualifyingData returns the 32-byte quote qualifying data
// SHA-256(Domain || 0x00 || SHA-256(receiptEnvelope) || SHA-256(challengeDocument)).
func QualifyingData(receiptEnvelope, challengeDocument []byte) []byte {
	receipt := sha256.Sum256(receiptEnvelope)
	challenge := sha256.Sum256(challengeDocument)
	h := sha256.New()
	h.Write([]byte(Domain))
	h.Write([]byte{0})
	h.Write(receipt[:])
	h.Write(challenge[:])
	return h.Sum(nil)
}

// KernelOptions returns the closed-grammar recovery kernel command line for a
// canonical lowercase UUID action and a qualified serial console ("" for none).
func KernelOptions(actionID, serialConsole string) (string, error) {
	if !canonicalUUID(actionID) {
		return "", errActionID
	}
	consoleOptions := ""
	switch serialConsole {
	case serialConsoles[0]:
	case serialConsoles[1], serialConsoles[2]:
		consoleOptions = " console=tty0 console=" + serialConsole
	default:
		return "", errSerialConsole
	}
	return kernelOptionsPrefix + consoleOptions + actionOption + actionID, nil
}

// ActionFromKernelOptions returns the action ID from options that exactly match
// the KernelOptions grammar.
func ActionFromKernelOptions(options string) (string, error) {
	if len(options) > maxKernelOptions {
		return "", errKernelOptions
	}
	index := strings.LastIndex(options, actionOption)
	if index < 0 {
		return "", errKernelOptions
	}
	actionID := options[index+len(actionOption):]
	if !canonicalUUID(actionID) {
		return "", errActionID
	}
	for _, console := range serialConsoles {
		if expected, err := KernelOptions(actionID, console); err == nil && expected == options {
			return actionID, nil
		}
	}
	return "", errKernelOptions
}

func canonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
