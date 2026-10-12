//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/platform"
)

type luksToken struct {
	Type      string   `json:"type"`
	Keyslots  []string `json:"keyslots"`
	KeySHA256 string   `json:"lindm-key-sha256,omitempty"`
	ActionID  string   `json:"lindm-action-id,omitempty"`
	PCRs      []uint32 `json:"tpm2-pcrs,omitempty"`
}

type luksMetadata struct {
	Keyslots map[string]json.RawMessage `json:"keyslots"`
	Tokens   map[string]luksToken       `json:"tokens"`
	Segments map[string]struct {
		Offset string `json:"offset"`
		Type   string `json:"type"`
	} `json:"segments"`
	Config struct {
		JSONSize string `json:"json_size"`
	} `json:"config"`
	// size is the canonical compact JSON length, set by Provider.metadata.
	size int
}

func parseMetadata(raw []byte) (*luksMetadata, error) {
	if len(raw) == 0 || len(raw) > outputLimit {
		return nil, ErrUnsupported
	}
	var metadata luksMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, fmt.Errorf("decode LUKS2 metadata: %w", err)
	}
	if metadata.Keyslots == nil || metadata.Tokens == nil || len(metadata.Keyslots) > 32 || len(metadata.Tokens) > 32 || len(metadata.Segments) != 1 {
		return nil, fmt.Errorf("%w: unsupported_luks_layout", ErrUnsupported)
	}
	for slot := range metadata.Keyslots {
		if _, err := slotNumber(slot); err != nil {
			return nil, err
		}
	}
	for id, token := range metadata.Tokens {
		if _, err := slotNumber(id); err != nil {
			return nil, err
		}
		if len(token.Keyslots) > 32 {
			return nil, ErrUnsupported
		}
		for _, slot := range token.Keyslots {
			if _, err := slotNumber(slot); err != nil {
				return nil, err
			}
			if _, ok := metadata.Keyslots[slot]; !ok {
				return nil, ErrConflict
			}
		}
	}
	return &metadata, nil
}

func slotNumber(text string) (uint32, error) {
	value, err := strconv.ParseUint(text, 10, 5)
	if err != nil || strconv.FormatUint(value, 10) != text {
		return 0, fmt.Errorf("%w: invalid_native_slot", ErrUnsupported)
	}
	return uint32(value), nil
}

// Only native token identity/type/slot references are public observation. Token
// payloads (TPM sealed objects, salts, key digests, credentials) never enter it.
func (p *Provider) populateLUKSObservation(observation *agentv1.DeviceActionObservation, metadata *luksMetadata, hash []byte) error {
	observation.Encrypted = true
	observation.MetadataSha256 = hash
	observation.LindmKeyslots = managedSlots(metadata)
	observation.OccupiedKeyslots = make([]uint32, 0, len(metadata.Keyslots))
	observation.LuksTokens = make([]*agentv1.LUKSTokenObservation, 0, len(metadata.Tokens))
	observation.Tpm2Bound = false
	for text := range metadata.Keyslots {
		slot, err := slotNumber(text)
		if err != nil {
			return err
		}
		observation.OccupiedKeyslots = append(observation.OccupiedKeyslots, slot)
	}
	slices.Sort(observation.OccupiedKeyslots)
	for text, token := range metadata.Tokens {
		id, err := slotNumber(text)
		if err != nil {
			return err
		}
		public := &agentv1.LUKSTokenObservation{TokenId: id, Type: token.Type, Keyslots: make([]uint32, 0, len(token.Keyslots))}
		for _, text := range token.Keyslots {
			slot, err := slotNumber(text)
			if err != nil {
				return err
			}
			public.Keyslots = append(public.Keyslots, slot)
		}
		slices.Sort(public.Keyslots)
		observation.LuksTokens = append(observation.LuksTokens, public)
		observation.Tpm2Bound = observation.Tpm2Bound || token.Type == "systemd-tpm2"
	}
	slices.SortFunc(observation.LuksTokens, func(left, right *agentv1.LUKSTokenObservation) int {
		return int(left.GetTokenId()) - int(right.GetTokenId())
	})
	return p.validate.Validate(observation)
}

func (p *Provider) metadata(ctx context.Context, file *os.File) (*luksMetadata, []byte, error) {
	raw, err := p.crypt(ctx, file, []string{"luksDump", "--type", "luks2", "--dump-json-metadata", descriptor(0)})
	if err != nil {
		return nil, nil, err
	}
	metadata, err := parseMetadata(raw)
	if err != nil {
		return nil, nil, err
	}
	// Canonical JSON prevents whitespace or native map ordering from changing the
	// precondition while retaining every field, not just the parsed safety subset.
	var document any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	hash := sha256.Sum256(canonical)
	metadata.size = len(canonical)
	return metadata, hash[:], nil
}

func managedSlots(metadata *luksMetadata) []uint32 {
	var result []uint32
	for _, token := range metadata.Tokens {
		if token.Type != "lindm-recovery" || len(token.Keyslots) != 1 || len(token.KeySHA256) != 64 {
			continue
		}
		if _, err := hex.DecodeString(token.KeySHA256); err != nil {
			continue
		}
		slot, err := slotNumber(token.Keyslots[0])
		if err == nil && !slices.Contains(result, slot) {
			result = append(result, slot)
		}
	}
	slices.Sort(result)
	return result
}

func ownerPresent(metadata *luksMetadata, owner uint32) bool {
	_, present := metadata.Keyslots[strconv.FormatUint(uint64(owner), 10)]
	return present && !slices.Contains(managedSlots(metadata), owner)
}

func (p *Provider) testUnlock(ctx context.Context, file *os.File, slot uint32, credential []byte) error {
	if len(credential) == 0 || len(credential) > 4096 {
		return ErrCredential
	}
	_, err := p.crypt(ctx, file, []string{"open", "--type", "luks2", "--test-passphrase", "--key-slot", strconv.FormatUint(uint64(slot), 10), "--key-file", descriptor(1), descriptor(0)}, credential)
	if err != nil {
		return fmt.Errorf("%w: unlock_credential_rejected", ErrConflict)
	}
	return nil
}

func freeSlot(metadata *luksMetadata) (uint32, error) {
	for slot := uint32(0); slot < 32; slot++ {
		if _, occupied := metadata.Keyslots[strconv.FormatUint(uint64(slot), 10)]; !occupied {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("%w: no_free_keyslot", ErrUnsupported)
}

func freeToken(metadata *luksMetadata) (uint32, error) {
	ids, err := freeTokens(metadata, 1)
	if err != nil {
		return 0, err
	}
	return ids[0], nil
}

// freeTokens returns the count lowest unused token IDs.
func freeTokens(metadata *luksMetadata, count int) ([]uint32, error) {
	ids := make([]uint32, 0, count)
	for id := uint32(0); id < 32 && len(ids) < count; id++ {
		if _, occupied := metadata.Tokens[strconv.FormatUint(uint64(id), 10)]; !occupied {
			ids = append(ids, id)
		}
	}
	if len(ids) < count {
		return nil, fmt.Errorf("%w: no_free_token", ErrUnsupported)
	}
	return ids, nil
}

// LUKS2 JSON a managed TPM2 bind adds: one keyslot (296 bytes as written by
// systemd-cryptenroll 255) and one systemd-tpm2 token per reference (738 bytes
// with an ECC SRK; an RSA SRK's serialized public area is larger).
const (
	tpm2KeyslotJSONBudget = 512
	tpm2TokenJSONBudget   = 1024
)

// tpm2CapacityReason refuses a bind whose keyslot, token references or JSON
// would not fit, before any effect: running out midway would leave fewer
// references than the release needs. Empty means the bind fits.
func tpm2CapacityReason(metadata *luksMetadata, references int) string {
	if _, err := freeSlot(metadata); err != nil {
		return "no_free_keyslot"
	}
	if _, err := freeTokens(metadata, references); err != nil {
		return "no_free_token"
	}
	area, err := strconv.Atoi(metadata.Config.JSONSize)
	if err != nil || area <= 0 || metadata.size <= 0 {
		return "luks2_json_area_unknown"
	}
	if area-metadata.size < tpm2KeyslotJSONBudget+references*tpm2TokenJSONBudget {
		return "luks2_metadata_space_exhausted"
	}
	return ""
}

// newTPMTokens returns, in token-ID order, the systemd-tpm2 tokens with exactly
// the requested PCRs that reference one keyslot absent before the bind.
func newTPMTokens(metadata *luksMetadata, occupiedBefore []uint32, pcrs []uint32) (slot uint32, ids []string, err error) {
	wanted := slices.Clone(pcrs)
	slices.Sort(wanted)
	found := false
	for id, token := range metadata.Tokens {
		actual := slices.Clone(token.PCRs)
		slices.Sort(actual)
		if token.Type != "systemd-tpm2" || !slices.Equal(wanted, actual) || len(token.Keyslots) != 1 {
			continue
		}
		tokenSlot, err := slotNumber(token.Keyslots[0])
		if err != nil {
			return 0, nil, err
		}
		if slices.Contains(occupiedBefore, tokenSlot) {
			continue
		}
		if found && tokenSlot != slot {
			return 0, nil, fmt.Errorf("%w: multiple_new_tpm2_keyslots", ErrConflict)
		}
		slot, found = tokenSlot, true
		ids = append(ids, id)
	}
	if !found {
		return 0, nil, ErrNotVerified
	}
	slices.SortFunc(ids, func(left, right string) int {
		l, _ := strconv.Atoi(left)
		r, _ := strconv.Atoi(right)
		return l - r
	})
	return slot, ids, nil
}

func (p *Provider) rotate(ctx context.Context, plan *agentv1.DeviceActionPlan, target *targetHandle, credential []byte, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	action := plan.GetSpec().GetEscrowRotate()
	metadata, digest, err := p.metadata(ctx, target.file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, plan.GetBefore().GetMetadataSha256()) || !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) {
		return nil, ErrConflict
	}
	if action.RetireKeyslot != nil && (!slices.Contains(managedSlots(metadata), action.GetRetireKeyslot()) || action.GetRetireKeyslot() == target.qualification.GetOwnerRecoveryKeyslot()) {
		return nil, ErrConflict
	}
	if err := p.testUnlock(ctx, target.file, target.qualification.GetOwnerRecoveryKeyslot(), credential); err != nil {
		return nil, err
	}
	slot, err := freeSlot(metadata)
	if err != nil {
		return nil, err
	}
	tokenID, err := freeToken(metadata)
	if err != nil {
		return nil, err
	}
	if p.seal == nil || plan.GetRecoveryBinding() == nil {
		return nil, fmt.Errorf("%w: escrow_custody_required", ErrUnsupported)
	}
	binding := proto.CloneOf(plan.GetRecoveryBinding())
	if binding.GetLuksUuid() != action.GetTarget().GetLuksUuid() || binding.GetActionId() != plan.GetActionId() || binding.GetNewKeyslot() != slot {
		return nil, ErrConflict
	}
	entropy, err := lockedMemory(32)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, releaseMemory(entropy)) }()
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	key, err := lockedMemory(hex.EncodedLen(len(entropy)))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, releaseMemory(key)) }()
	hex.Encode(key, entropy)
	keyHash := sha256.Sum256(key)
	ciphertext, err := p.seal(ctx, binding, plan.GetSpec(), key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext) > 16384 {
		return nil, ErrUnsupported
	}
	if err := gate(ctx); err != nil {
		return nil, err
	}
	if _, err := p.crypt(ctx, target.file, []string{"luksAddKey", "--type", "luks2", "--batch-mode", "--key-slot", strconv.FormatUint(uint64(slot), 10), "--key-file", descriptor(1), descriptor(0), descriptor(2)}, credential, key); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if err := p.testUnlock(ctx, target.file, slot, key); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	token := luksToken{Type: "lindm-recovery", Keyslots: []string{strconv.FormatUint(uint64(slot), 10)}, KeySHA256: hex.EncodeToString(keyHash[:]), ActionID: plan.GetActionId()}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if _, err := p.run(ctx, nativeRequest{command: cryptsetup, args: []string{"token", "import", "--token-id", strconv.FormatUint(uint64(tokenID), 10), "--json-file", "-", descriptor(0)}, files: []*os.File{target.file}, input: tokenJSON}); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	updated, updatedHash, err := p.metadata(ctx, target.file)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !ownerPresent(updated, target.qualification.GetOwnerRecoveryKeyslot()) || !slices.Contains(managedSlots(updated), slot) {
		return nil, ErrOutcomeUnknown
	}
	if action.RetireKeyslot != nil && !slices.Contains(managedSlots(updated), action.GetRetireKeyslot()) {
		return nil, ErrOutcomeUnknown
	}
	after := proto.CloneOf(plan.GetBefore())
	if err := p.populateLUKSObservation(after, updated, updatedHash); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	return &agentv1.DeviceActionVerification{After: after, Evidence: "Replacement key unlock tested; independent owner and prior managed slot retained; awaiting authenticated durable escrow receipt.", Escrow: &agentv1.DeviceActionEscrow{EscrowKeyId: action.GetEscrowKeyId(), Ciphertext: ciphertext, RecoveryKeySha256: keyHash[:], NewKeyslot: slot, LuksUuid: action.GetTarget().GetLuksUuid(), MetadataSha256: updatedHash, TokenId: tokenID}}, nil
}

func (p *Provider) bindTPM(ctx context.Context, plan *agentv1.DeviceActionPlan, target *targetHandle, credential []byte, gate func(context.Context) error) (err error) {
	metadata, hash, err := p.metadata(ctx, target.file)
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, plan.GetBefore().GetMetadataSha256()) || !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) {
		return ErrConflict
	}
	if err := p.testUnlock(ctx, target.file, target.qualification.GetOwnerRecoveryKeyslot(), credential); err != nil {
		return err
	}
	references, err := p.tpm2References()
	if err != nil {
		return err
	}
	if reason := tpm2CapacityReason(metadata, references); reason != "" {
		return fmt.Errorf("%w: %s", ErrUnsupported, reason)
	}
	pcrs := make([]string, len(plan.GetSpec().GetTpm2Bind().GetPcrs()))
	for i, pcr := range plan.GetSpec().GetTpm2Bind().GetPcrs() {
		pcrs[i] = strconv.FormatUint(uint64(pcr), 10)
	}
	args := []string{"--unlock-key-file=" + descriptor(1), "--tpm2-device=auto", "--tpm2-pcrs=" + strings.Join(pcrs, "+")}
	if p.pcrlockPolicy == nil {
		return ErrUnsupported
	}
	pcrlock, err := p.pcrlockPolicy()
	if err != nil {
		return err
	}
	if pcrlock {
		// Keep the sealed policy exactly the approved PCRs: an empty value
		// turns off cryptenroll's automatic pcrlock policy.
		args = append(args, "--tpm2-pcrlock=")
	}
	secret, err := secretFile(credential)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, secret.Close()) }()
	if err := gate(ctx); err != nil {
		return err
	}
	_, err = p.run(ctx, nativeRequest{command: cryptenroll, args: append(args, descriptor(0)), files: []*os.File{target.file, secret.file}})
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if references > 1 {
		if err := p.referenceTPMToken(ctx, target, plan, references); err != nil {
			return errors.Join(ErrOutcomeUnknown, err)
		}
	}
	return nil
}

// pcrlockPolicyPresent reports a systemd-pcrlock policy file in the paths
// systemd-cryptenroll searches. Whenever one exists (the Tumbleweed encrypted
// guest carried /var/lib/systemd/pcrlock.json) cryptenroll silently
// adds that policy to a --tpm2-pcrs= enrollment, so the token no longer
// unseals under the approved PCRs alone: a bind after a deliberate PCR 7
// change failed its own token-only verification ("None of the alternative
// values for PCR 7 encoded in policy match"). The file exists only with
// systemd 255 or later, which accepts --tpm2-pcrlock=.
func pcrlockPolicyPresent() (bool, error) {
	for _, path := range []string{"/run/systemd/pcrlock.json", "/var/lib/systemd/pcrlock.json"} {
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// referenceTPMToken adds references-1 byte-identical copies of the token
// systemd-cryptenroll just wrote, all naming its one new keyslot: the same
// sealed object and PCR policy, opened with fresh TPM sessions per token
// (platform.TPM2UnsealRetryNextToken). No secret is written; the export holds
// only the TPM-sealed object, which never leaves the agent.
func (p *Provider) referenceTPMToken(ctx context.Context, target *targetHandle, plan *agentv1.DeviceActionPlan, references int) error {
	metadata, _, err := p.metadata(ctx, target.file)
	if err != nil {
		return err
	}
	_, ids, err := newTPMTokens(metadata, plan.GetBefore().GetOccupiedKeyslots(), plan.GetSpec().GetTpm2Bind().GetPcrs())
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		return fmt.Errorf("%w: unexpected_tpm2_token_references", ErrConflict)
	}
	sealed, err := p.crypt(ctx, target.file, []string{"token", "export", "--token-id", ids[0], descriptor(0)})
	if err != nil {
		return err
	}
	free, err := freeTokens(metadata, references-1)
	if err != nil {
		return err
	}
	for _, id := range free {
		if _, err := p.run(ctx, nativeRequest{command: cryptsetup, args: []string{"token", "import", "--token-id", strconv.FormatUint(uint64(id), 10), "--json-file", "-", descriptor(0)}, files: []*os.File{target.file}, input: sealed}); err != nil {
			return err
		}
	}
	return nil
}

// tpm2References is the registry's token-reference count for this host's own
// os-release row (platform.Release.TPM2TokenReferences).
func (p *Provider) tpm2References() (int, error) {
	if p.hostRelease == nil {
		return 0, fmt.Errorf("%w: host_release_unknown", ErrUnsupported)
	}
	release, err := p.hostRelease()
	if err != nil {
		return 0, err
	}
	return release.TPM2TokenReferences(), nil
}

const maximumOSRelease = 64 << 10

// readHostRelease maps /etc/os-release to its registry row; an unlisted
// release is a valid, unknown row.
func readHostRelease() (_ *platform.Release, err error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(io.LimitReader(file, maximumOSRelease+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximumOSRelease {
		return nil, fmt.Errorf("%w: os_release_too_large", ErrUnsupported)
	}
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = strings.Trim(value, "\"'")
		}
	}
	return platform.Identify(platform.OSRelease{ID: fields["ID"], VersionID: fields["VERSION_ID"], VariantID: fields["VARIANT_ID"]}), nil
}

// cryptenrollBindsTPM2 is the native probe behind the server's registry gate:
// the installed systemd-cryptenroll must be at least platform's
// TPM2BindSystemdFloor (descriptor unlock and the TPM2 token plugin). Without
// it binding would fail only after authorization, as an unknown outcome.
// Unparseable output is not a capability.
func cryptenrollBindsTPM2(version []byte) bool {
	line, _, _ := strings.Cut(string(version), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "systemd" {
		return false
	}
	major := fields[1]
	if end := strings.IndexFunc(major, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		major = major[:end]
	}
	release, err := strconv.Atoi(major)
	return err == nil && release >= platform.TPM2BindSystemdFloor
}

// ConfirmEscrow trusts only the executor's receipt-authentication gate. The gate
// must durably record retirement intent before returning. No callback, wrong
// metadata, missing credential, or crash is allowed to retire either recovery slot.
func (p *Provider) ConfirmEscrow(ctx context.Context, plan *agentv1.DeviceActionPlan, stage *agentv1.DeviceActionVerification, credential []byte, gate func(context.Context) error) (_ *agentv1.DeviceActionVerification, err error) {
	ctx, done, err := p.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := p.validatePlan(plan); err != nil {
		return nil, err
	}
	if stage == nil || stage.GetEscrow() == nil || gate == nil || plan.GetSpec().GetEscrowRotate() == nil {
		return nil, ErrConflict
	}
	if err := p.validate.Validate(stage); err != nil {
		return nil, err
	}
	action, escrow := plan.GetSpec().GetEscrowRotate(), stage.GetEscrow()
	if plan.GetRecoveryBinding() == nil || escrow.GetNewKeyslot() != plan.GetRecoveryBinding().GetNewKeyslot() || escrow.GetLuksUuid() != action.GetTarget().GetLuksUuid() || escrow.GetEscrowKeyId() != action.GetEscrowKeyId() || !bytes.Equal(stage.GetAfter().GetMetadataSha256(), escrow.GetMetadataSha256()) {
		return nil, ErrConflict
	}
	target, err := p.resolve(ctx, plan.GetSpec(), true)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, target.file.Close()) }()
	if !target.qualification.GetAllowRecoveryRotation() {
		return nil, ErrUnsupported
	}
	metadata, hash, err := p.metadata(ctx, target.file)
	if err != nil {
		return nil, err
	}
	token, exists := metadata.Tokens[strconv.FormatUint(uint64(escrow.GetTokenId()), 10)]
	if !exists || token.Type != "lindm-recovery" || token.ActionID != plan.GetActionId() || token.KeySHA256 != hex.EncodeToString(escrow.GetRecoveryKeySha256()) || len(token.Keyslots) != 1 || token.Keyslots[0] != strconv.FormatUint(uint64(escrow.GetNewKeyslot()), 10) || !bytes.Equal(hash, escrow.GetMetadataSha256()) || !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) {
		return nil, ErrConflict
	}
	priorTokens := metadata.Tokens
	var retiredTokenIDs []string
	if action.RetireKeyslot != nil {
		old := action.GetRetireKeyslot()
		if old == escrow.GetNewKeyslot() || old == target.qualification.GetOwnerRecoveryKeyslot() || !slices.Contains(managedSlots(metadata), old) {
			return nil, ErrConflict
		}
		oldText := strconv.FormatUint(uint64(old), 10)
		for id, prior := range priorTokens {
			if id != strconv.FormatUint(uint64(escrow.GetTokenId()), 10) && prior.Type == "lindm-recovery" && len(prior.Keyslots) == 1 && prior.Keyslots[0] == oldText {
				if _, err := hex.DecodeString(prior.KeySHA256); len(prior.KeySHA256) != 64 || err != nil {
					continue
				}
				retiredTokenIDs = append(retiredTokenIDs, id)
			}
		}
		slices.Sort(retiredTokenIDs)
		if err := p.testUnlock(ctx, target.file, target.qualification.GetOwnerRecoveryKeyslot(), credential); err != nil {
			return nil, err
		}
		if err := gate(ctx); err != nil {
			return nil, err
		}
		if _, err := p.crypt(ctx, target.file, []string{"luksKillSlot", "--batch-mode", "--key-file", descriptor(1), descriptor(0), strconv.FormatUint(uint64(old), 10)}, credential); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	} else if err := gate(ctx); err != nil {
		return nil, err
	}
	metadata, hash, err = p.metadata(ctx, target.file)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) || !slices.Contains(managedSlots(metadata), escrow.GetNewKeyslot()) {
		return nil, ErrOutcomeUnknown
	}
	if action.RetireKeyslot != nil {
		if _, exists := metadata.Keyslots[strconv.FormatUint(uint64(action.GetRetireKeyslot()), 10)]; exists {
			return nil, ErrOutcomeUnknown
		}
	}
	// cryptsetup unassigns the wiped slot but retains its now-empty token object.
	// Reclaim only exact pre-retirement lindm-owned tokens so repeated rotations
	// do not exhaust the finite token namespace. Never touch unrelated tokens.
	for _, id := range retiredTokenIDs {
		current, exists := metadata.Tokens[id]
		prior := priorTokens[id]
		if !exists {
			continue
		}
		if len(current.Keyslots) != 0 || current.Type != prior.Type || current.KeySHA256 != prior.KeySHA256 || current.ActionID != prior.ActionID || !slices.Equal(current.PCRs, prior.PCRs) {
			return nil, ErrOutcomeUnknown
		}
	}
	for _, id := range retiredTokenIDs {
		if _, exists := metadata.Tokens[id]; !exists {
			continue
		}
		if _, err := p.crypt(ctx, target.file, []string{"token", "remove", "--token-id", id, descriptor(0)}); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if len(retiredTokenIDs) != 0 {
		metadata, hash, err = p.metadata(ctx, target.file)
		if err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		if !ownerPresent(metadata, target.qualification.GetOwnerRecoveryKeyslot()) || !slices.Contains(managedSlots(metadata), escrow.GetNewKeyslot()) {
			return nil, ErrOutcomeUnknown
		}
		for _, id := range retiredTokenIDs {
			if _, exists := metadata.Tokens[id]; exists {
				return nil, ErrOutcomeUnknown
			}
		}
	}
	result := proto.CloneOf(stage)
	result.Verified = true
	if err := p.populateLUKSObservation(result.After, metadata, hash); err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	result.Evidence = "Replacement unlock tested before durable escrow receipt; retirement verified; independent owner recovery slot retained. Cold-boot recovery is separate evidence."
	return result, nil
}
