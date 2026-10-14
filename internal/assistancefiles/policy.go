// SPDX-License-Identifier: Apache-2.0

// Package assistancefiles enforces file metadata authority shared by the server,
// root broker and unprivileged helper. It never opens files or transports bytes.
package assistancefiles

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const (
	MaxFileBytes    uint64 = 16 << 20
	MaxSessionBytes uint64 = 64 << 20
	MaxOperations          = 32
	ChunkBytes             = 16 << 10
	FrameBytes             = 17408
	QueueSize              = 8
	BufferedBytes          = 128 << 10
)

func Intersect(a, b *agentv1.AssistanceFilePolicy) *agentv1.AssistanceFilePolicy {
	if a.GetMaxFileBytes() == 0 || b.GetMaxFileBytes() == 0 || a.GetMaxSessionBytes() == 0 || b.GetMaxSessionBytes() == 0 {
		return nil
	}
	p := &agentv1.AssistanceFilePolicy{MaxFileBytes: min(a.GetMaxFileBytes(), b.GetMaxFileBytes(), MaxFileBytes), MaxSessionBytes: min(a.GetMaxSessionBytes(), b.GetMaxSessionBytes(), MaxSessionBytes)}
	p.MaxFileBytes = min(p.MaxFileBytes, p.MaxSessionBytes)
	for _, value := range a.GetAllowedMimeTypes() {
		if Recognized(value) && slices.Contains(b.GetAllowedMimeTypes(), value) && !slices.Contains(p.AllowedMimeTypes, value) {
			p.AllowedMimeTypes = append(p.AllowedMimeTypes, value)
		}
	}
	for _, value := range a.GetAllowedExtensions() {
		if slices.Contains(b.GetAllowedExtensions(), value) && !slices.Contains(p.AllowedExtensions, value) {
			p.AllowedExtensions = append(p.AllowedExtensions, value)
		}
	}
	if len(p.AllowedMimeTypes) == 0 || len(p.AllowedExtensions) == 0 {
		return nil
	}
	return p
}

func Recognized(value string) bool {
	switch value {
	case "text/plain", "application/pdf", "image/png", "image/jpeg":
		return true
	default:
		return false
	}
}

func Allowed(p *agentv1.AssistanceFilePolicy, contentType, extension string) bool {
	return p != nil && Recognized(contentType) && slices.Contains(p.GetAllowedMimeTypes(), contentType) && slices.Contains(p.GetAllowedExtensions(), extension)
}

func SafeName(name string) bool {
	if name == "" || len(name) > 240 || strings.HasPrefix(name, ".") || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func MetadataAllowed(p *agentv1.AssistanceFilePolicy, file *agentv1.AssistanceFileMetadata, digestRequired bool) bool {
	return file != nil && SafeName(file.GetName()) && p.GetMaxFileBytes() > 0 && file.GetSize() <= min(p.GetMaxFileBytes(), MaxFileBytes) && (!digestRequired || len(file.GetSha256()) == 32) && (len(file.GetSha256()) == 0 || len(file.GetSha256()) == 32) && Allowed(p, file.GetMimeType(), strings.ToLower(filepath.Ext(file.GetName())))
}

func DirectionAllowed(mode agentv1.AssistancePolicyMode, direction agentv1.AssistanceFileDirection) bool {
	switch direction {
	case agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER:
		return mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_LIMITED || mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	case agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER:
		return mode == agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_ON
	default:
		return false
	}
}

func Terminal(state agentv1.AssistanceFileState) bool {
	return state >= agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_SUCCEEDED && state <= agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED
}
