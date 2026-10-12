// Package demolab loads declarative organization demos and admits only qualified
// release/architecture capabilities. It neither provisions devices nor manufactures
// qualification evidence; execution and ledger acquisition belong to the caller.
package demolab

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/orgapply"
	"lindm/internal/platform"
	"lindm/internal/vmlab"
)

// Spec retains the validated document and its resolved inputs. Callers must not
// mutate these inputs between admission and execution.
type Spec struct {
	Document         *labv1.DemoSpec
	Organization     *orgv1.Organization
	OrganizationPath string
	Devices          []Device
}

// Device binds a document entry to its loaded manifest and registry identity.
type Device struct {
	Config       *labv1.DemoDevice
	Manifest     *labv1.ImageManifest
	ManifestPath string
	Release      *platform.Release
	Architecture string
}

// Load strictly decodes and validates the demo and organization, resolves file
// references relative to the demo document, and checks enrollment membership.
// Host firmware paths are interpreted by the execution host and remain unchanged.
func Load(path string) (*Spec, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("demo: resolve document: %w", err)
	}
	data, err := readDocument(path)
	if err != nil {
		return nil, err
	}
	document := new(labv1.DemoSpec)
	if err := protojson.Unmarshal(data, document); err != nil {
		return nil, fmt.Errorf("demo: decode %s: %w", path, err)
	}
	if err := protovalidate.Validate(document); err != nil {
		return nil, fmt.Errorf("demo: validate %s: %w", path, err)
	}
	orgPath := resolve(filepath.Dir(path), document.GetOrganization())
	data, err = readDocument(orgPath)
	if err != nil {
		return nil, err
	}
	organization, err := orgapply.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("demo: organization %s: %w", orgPath, err)
	}
	spec := &Spec{Document: document, Organization: organization, OrganizationPath: orgPath, Devices: make([]Device, 0, len(document.GetDevices()))}
	for _, config := range document.GetDevices() {
		if err := enrollment(organization, config); err != nil {
			return nil, err
		}
		manifestPath := resolve(filepath.Dir(path), config.GetManifest())
		manifest, err := vmlab.LoadManifest(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("demo: device %s manifest: %w", config.GetKey(), err)
		}
		release := platform.ForManifest(manifest.GetDistribution(), manifest.GetVersion())
		architecture := manifest.GetArchitecture()
		switch architecture {
		case "amd64":
			architecture = "x86_64"
		case "arm64":
			architecture = "aarch64"
		}
		if !release.Known() || !slices.Contains(release.Architectures, architecture) {
			return nil, fmt.Errorf("demo: device %s manifest has unregistered release/architecture %s %s/%s", config.GetKey(), manifest.GetDistribution(), manifest.GetVersion(), architecture)
		}
		spec.Devices = append(spec.Devices, Device{Config: config, Manifest: manifest, ManifestPath: manifestPath, Release: release, Architecture: architecture})
	}
	return spec, nil
}

func enrollment(organization *orgv1.Organization, device *labv1.DemoDevice) error {
	if !slices.ContainsFunc(organization.GetGroups(), func(group *orgv1.StaticGroup) bool { return group.GetId() == device.GetGroup() }) {
		return fmt.Errorf("demo: device %s static group %s does not exist in organization", device.GetKey(), device.GetGroup())
	}
	for _, token := range organization.GetProvisioningTokens() {
		if token.GetName() != device.GetProvisioningToken() {
			continue
		}
		if !slices.Contains(token.GetRequest().GetGroupIds(), device.GetGroup()) {
			return fmt.Errorf("demo: device %s provisioning token %s does not assign static group %s", device.GetKey(), token.GetName(), device.GetGroup())
		}
		return nil
	}
	return fmt.Errorf("demo: device %s provisioning token %s does not exist in organization", device.GetKey(), device.GetProvisioningToken())
}

func resolve(directory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(directory, path)
}

func readDocument(path string) (_ []byte, err error) {
	const maxBytes = 16 << 20
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("demo: open %s: %w", path, err)
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("demo: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, fmt.Errorf("demo: %s must be a regular file of at most %d bytes", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("demo: read %s: %w", path, err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("demo: %s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}
