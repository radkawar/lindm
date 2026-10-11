package measuredboot

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestValidateAttestationKey(t *testing.T) {
	ak := newSoftwareAK(t, nil)
	key, err := ValidateAttestationKey(ak.public)
	if err != nil {
		t.Fatalf("ValidateAttestationKey: %v", err)
	}
	if !key.Equal(&ak.key.PublicKey) {
		t.Fatal("ValidateAttestationKey returned a different key")
	}
	eccParameters := func(mutate func(*tpm2.TPMSECCParms)) func(*tpm2.TPMTPublic) {
		return func(public *tpm2.TPMTPublic) {
			parameters, err := public.Parameters.ECCDetail()
			if err != nil {
				t.Fatal(err)
			}
			mutate(parameters)
		}
	}
	for name, test := range map[string]struct {
		mutate func(*tpm2.TPMTPublic)
		want   error
	}{
		"name alg sha1":  {func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA1 }, errAttestationKeyType},
		"not restricted": {func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = false }, errAttestationKeyAttributes},
		"decrypt":        {func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true }, errAttestationKeyAttributes},
		"no DA":          {func(p *tpm2.TPMTPublic) { p.ObjectAttributes.NoDA = true }, errAttestationKeyAttributes},
		"not fixed TPM":  {func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false }, errAttestationKeyAttributes},
		"auth policy":    {func(p *tpm2.TPMTPublic) { p.AuthPolicy.Buffer = make([]byte, 32) }, errAttestationKeyPolicy},
		"curve P-384":    {eccParameters(func(p *tpm2.TPMSECCParms) { p.CurveID = tpm2.TPMECCNistP384 }), errAttestationKeyParameters},
		"symmetric": {eccParameters(func(p *tpm2.TPMSECCParms) {
			p.Symmetric = tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgAES, KeyBits: tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)), Mode: tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB)}
		}), errAttestationKeyParameters},
		"scheme sha384": {eccParameters(func(p *tpm2.TPMSECCParms) {
			p.Scheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA384})
		}), errAttestationKeyParameters},
		"null scheme":     {eccParameters(func(p *tpm2.TPMSECCParms) { p.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull} }), errAttestationKeyParameters},
		"point off curve": {func(p *tpm2.TPMTPublic) { p.Unique = eccPoint(1, 1) }, errAttestationKeyPoint},
		"short point":     {func(p *tpm2.TPMTPublic) { p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}) }, errAttestationKeyPoint},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateAttestationKey(newSoftwareAK(t, test.mutate).public); !errors.Is(err, test.want) {
				t.Fatalf("ValidateAttestationKey error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := ValidateAttestationKey(append(bytes.Clone(ak.public), 0)); !errors.Is(err, errAttestationKeyEncoding) {
		t.Fatalf("trailing byte error = %v", err)
	}
	if _, err := ValidateAttestationKey(ak.public[:len(ak.public)-1]); !errors.Is(err, errAttestationKeyEncoding) {
		t.Fatalf("truncated error = %v", err)
	}
}

func eccPoint(x, y byte) tpm2.TPMUPublicID {
	coordinate := func(value byte) tpm2.TPM2BECCParameter {
		buffer := make([]byte, 32)
		buffer[31] = value
		return tpm2.TPM2BECCParameter{Buffer: buffer}
	}
	return tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{X: coordinate(x), Y: coordinate(y)})
}

func TestVerifyAcceptsFixtureQuote(t *testing.T) {
	ak := newSoftwareAK(t, nil)
	qualifyingData := QualifyingData([]byte("receipt"), []byte("challenge"))
	evidence := ak.quoteFor(t, qualifyingData, fixtureLog(t), QuotePCRs[:]...)
	if err := Verify(fixtureExpected(t, ak, qualifyingData), evidence); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := VerifyQuoteSignature(ak.public, evidence.Quote, evidence.Signature); err != nil {
		t.Fatalf("VerifyQuoteSignature: %v", err)
	}
}

func TestVerifyAcceptsRecoveryEntry(t *testing.T) {
	options, err := KernelOptions(testAction, "ttyS0,115200n8")
	if err != nil {
		t.Fatal(err)
	}
	const device = "(hd0,gpt3)"
	initrdPath := "/boot/lindm-recovery-" + testAction + ".initrd"
	initrd := []byte("lindm recovery initramfs")
	events := fixtureEvents(t)
	events = replaceEvents(events, fixtureLinuxIndex, fixtureInitrdIndex+1,
		grubCommand(t, "grub_cmd: linux "+device+fixtureKernelPath+" "+options),
		events[fixtureKernelIndex],
		events[fixtureKernelIndex+1],
		grubCommand(t, "kernel_cmdline: "+device+fixtureKernelPath+" "+options),
		grubCommand(t, "grub_cmd: initrd "+device+initrdPath),
		grubFile(device+initrdPath, initrd),
	)
	ak := newSoftwareAK(t, nil)
	qualifyingData := QualifyingData([]byte("receipt"), []byte("challenge"))
	evidence := ak.quoteFor(t, qualifyingData, encodeEventLog(t, events), QuotePCRs[:]...)
	initrdDigest := sha256.Sum256(initrd)
	expected := fixtureExpected(t, ak, qualifyingData)
	expected.KernelOptions = options
	expected.InitrdPath = initrdPath
	expected.InitrdSHA256 = initrdDigest[:]
	if err := Verify(expected, evidence); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	ak := newSoftwareAK(t, nil)
	qualifyingData := QualifyingData([]byte("receipt"), []byte("challenge"))
	log := fixtureLog(t)
	valid := ak.quoteFor(t, qualifyingData, log, QuotePCRs[:]...)
	expected := fixtureExpected(t, ak, qualifyingData)
	events := fixtureEvents(t)

	resigned := func(events []Event) Evidence {
		return ak.quoteFor(t, qualifyingData, encodeEventLog(t, events), QuotePCRs[:]...)
	}
	secureBootOff := events[fixtureSecureBoot]
	secureBootOff.Data = bytes.Clone(secureBootOff.Data)
	secureBootOff.Data[len(secureBootOff.Data)-1] = 0
	secureBootDigest := sha256.Sum256(secureBootOff.Data)
	secureBootOff.SHA256 = secureBootDigest[:]

	tamperedLog := encodeEventLog(t, replaceEvents(events, 43, 44, grubCommand(t, "grub_cmd: search --fs-uuid --set=root evil")))
	badSignature := bytes.Clone(valid.Signature)
	badSignature[len(badSignature)-1] ^= 1
	otherKey := newSoftwareAK(t, nil)
	nonRestricted := newSoftwareAK(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = false })
	wrongKernel := expected
	wrongKernel.KernelSHA256 = bytes.Repeat([]byte{1}, 32)
	wrongInitrd := expected
	wrongInitrd.InitrdSHA256 = bytes.Repeat([]byte{2}, 32)
	wrongOptions := expected
	wrongOptions.KernelOptions += " quiet"
	wrongKernelPath := expected
	wrongKernelPath.KernelPath = "/boot/vmlinuz-other"
	wrongInitrdPath := expected
	wrongInitrdPath.InitrdPath = "/boot/other.img"
	nonRestrictedExpected := expected
	nonRestrictedExpected.AttestationKeyPublic = nonRestricted.public
	shortQualifyingData := expected
	shortQualifyingData.QualifyingData = qualifyingData[:31]

	for name, test := range map[string]struct {
		expected Expected
		evidence Evidence
		reason   string
	}{
		"wrong qualifying data": {expected, ak.quoteFor(t, QualifyingData([]byte("other"), []byte("challenge")), log, QuotePCRs[:]...), "quote_qualifying_data"},
		"wrong pcr selection":   {expected, ak.quoteFor(t, qualifyingData, log, 4, 7, 8), "quote_pcr_selection"},
		"extra pcr selection":   {expected, ak.quoteFor(t, qualifyingData, log, 4, 7, 8, 9, 14), "quote_pcr_selection"},
		"tampered log":          {expected, Evidence{Quote: valid.Quote, Signature: valid.Signature, EventLog: tamperedLog}, "quote_pcr_digest"},
		"truncated log":         {expected, Evidence{Quote: valid.Quote, Signature: valid.Signature, EventLog: log[:len(log)-1]}, "event_log"},
		"wrong signature":       {expected, Evidence{Quote: valid.Quote, Signature: badSignature, EventLog: log}, "quote_signature"},
		"other key signature":   {expected, otherKey.quoteFor(t, qualifyingData, log, QuotePCRs[:]...), "quote_signature"},
		"quote trailing byte":   {expected, Evidence{Quote: append(bytes.Clone(valid.Quote), 0), Signature: ak.sign(t, append(bytes.Clone(valid.Quote), 0)), EventLog: log}, "quote_encoding"},
		"wrong kernel digest":   {wrongKernel, valid, "kernel_digest"},
		"wrong initrd digest":   {wrongInitrd, valid, "initrd_digest"},
		"wrong kernel options":  {wrongOptions, valid, "kernel_options"},
		"wrong kernel path":     {wrongKernelPath, valid, "kernel_path"},
		"wrong initrd path":     {wrongInitrdPath, valid, "initrd_path"},
		"secure boot disabled": {
			expected, resigned(replaceEvents(events, fixtureSecureBoot, fixtureSecureBoot+1, secureBootOff)), "secure_boot",
		},
		"replaced initrd": {
			expected, resigned(replaceEvents(events, fixtureInitrdIndex, fixtureInitrdIndex+1, grubFile("(hd0,gpt3)"+fixtureInitrdPath, []byte("evil")))), "initrd_digest",
		},
		"appended initrd": {
			expected, resigned(append(events[:len(events):len(events)], grubCommand(t, "grub_cmd: initrd (hd0,gpt3)/boot/evil.img"))), "grub_boot",
		},
		"non-restricted key":     {nonRestrictedExpected, nonRestricted.quoteFor(t, qualifyingData, log, QuotePCRs[:]...), "attestation_key"},
		"short qualifying data":  {shortQualifyingData, valid, "expected_invalid"},
		"empty evidence":         {expected, Evidence{}, "quote_signature"},
		"signature over nothing": {expected, Evidence{Quote: valid.Quote, Signature: ak.sign(t, nil), EventLog: log}, "quote_signature"},
	} {
		t.Run(name, func(t *testing.T) {
			err := Verify(test.expected, test.evidence)
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), ErrRejected.Error()+": "+test.reason) {
				t.Fatalf("Verify error = %v, want %s", err, test.reason)
			}
		})
	}
}
