package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/demolab"
	"lindm/internal/orgapply"
	"lindm/internal/vmlab"
)

type demoOwnerAccess struct {
	ConsoleOrigin       string                           `json:"console_origin"`
	Username            string                           `json:"username"`
	EnrollmentSecret    string                           `json:"enrollment_secret"`
	EnrollmentStarted   bool                             `json:"enrollment_started"`
	EnrollmentExpiresAt time.Time                        `json:"enrollment_expires_at"`
	Secrets             []orgapply.Secret                `json:"organization_secrets"`
	Devices             map[string]*vmlab.AssistanceHold `json:"devices"`
}

// Rollout creation freezes its first ring and therefore requires real cohort
// inventory. Keep the declared canary gates intact; apply these dependencies
// from the original organization only after its machines are enrolled.
func demoPrerequisiteOrganization(organization *orgv1.Organization) *orgv1.Organization {
	prerequisites := proto.CloneOf(organization)
	prerequisites.Rollouts, prerequisites.Assignments = nil, nil
	return prerequisites
}

func readDemoPrivate(path string) (_ []byte, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("demo state must be an owned private bounded regular file")
	}
	return io.ReadAll(io.LimitReader(file, (1<<20)+1))
}

// publishDemoFile checkpoints secrets even after a partially successful apply.
// The caller holds the stable lifecycle lock; rename never writes through links.
func publishDemoFile(path string, data []byte, mode os.FileMode) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(file.Name()))
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func publishDemoJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	defer clear(data)
	return publishDemoFile(path, append(data, '\n'), mode)
}

func readDemoState(root string) (*labv1.DemoState, error) {
	data, err := readDemoPrivate(filepath.Join(root, "demo-state.json"))
	if err != nil {
		return nil, err
	}
	state := new(labv1.DemoState)
	// States written before provider opt-ins moved to signed capability
	// policies still carry the retired DemoDevice fields 11 and 12.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, state); err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(state); err != nil {
		return nil, err
	}
	return state, nil
}

// matchDemoState requires each bound device's immutable configuration.
func matchDemoState(state *labv1.DemoState, spec *demolab.Spec) error {
	if len(state.GetBindings()) != len(spec.Devices) {
		return errors.New("named demo device set changed; destroy the original before replacing devices")
	}
	byKey := make(map[string]*labv1.DemoBinding, len(state.Bindings))
	for _, bound := range state.Bindings {
		byKey[bound.Key] = bound
	}
	for _, device := range spec.Devices {
		bound := byKey[device.Config.GetKey()]
		if bound == nil || bound.GetManifestSha256() != device.Manifest.GetSha256() || !proto.Equal(bound.GetDevice(), device.Config) {
			return fmt.Errorf("named device %s changed its immutable configuration; destroy before replacing it", device.Config.GetKey())
		}
	}
	return nil
}

func bindDemoState(name, root string, spec *demolab.Spec, cfg *labv1.LabConfig) (*labv1.DemoState, error) {
	state, err := readDemoState(root)
	if err == nil {
		return state, matchDemoState(state, spec)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// A controller without bindings cannot safely infer which remote disks it owns.
	if _, err := os.Lstat(filepath.Join(root, "control-plane")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("existing controller has no organization device bindings")
	}
	state, err = planDemoBindings(name, spec, cfg)
	if err != nil {
		return nil, err
	}
	if err := protovalidate.Validate(state); err != nil {
		return nil, err
	}
	data, err := protojson.Marshal(state)
	if err != nil {
		return nil, err
	}
	return state, publishDemoFile(filepath.Join(root, "demo-state.json"), data, 0600)
}

func demoToken(access *demoOwnerAccess, name string) string {
	for _, secret := range access.Secrets {
		if secret.Kind == "provisioning_token" && secret.Name == name {
			return secret.Value
		}
	}
	return ""
}
