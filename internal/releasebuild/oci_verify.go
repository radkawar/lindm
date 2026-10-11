//go:build linux

package releasebuild

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"

	releasev1 "lindm/gen/lindm/release/v1"
)

// External OCI descriptor schema; release exports deliberately use one static,
// uncompressed layer and a deterministic member order rather than arbitrary
// third-party image layouts.
type imageDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func verifyOCICA(path string, artifact *releasev1.ReleaseArtifact, bom, provenance json.RawMessage) error {
	var build struct {
		Definition struct {
			Dependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
	}
	if err := json.Unmarshal(provenance, &build); err != nil {
		return err
	}
	pin := ""
	for _, dependency := range build.Definition.Dependencies {
		if dependency.URI == "urn:lindm:explicit-oci-ca-bundle" {
			if pin != "" {
				return errors.New("releasebuild: duplicate OCI CA provenance")
			}
			pin = dependency.Digest["sha256"]
		}
	}
	normalized, err := normalizeSHA256(pin)
	if err != nil {
		return errors.New("releasebuild: OCI CA provenance binding missing")
	}
	var sbom struct {
		Components []struct {
			Type, Name string
			Hashes     []struct {
				Algorithm string `json:"alg"`
				Content   string `json:"content"`
			}
		}
	}
	if err := json.Unmarshal(bom, &sbom); err != nil {
		return err
	}
	found := false
	for _, component := range sbom.Components {
		if component.Name == "/etc/ssl/certs/ca-certificates.crt" {
			if found || component.Type != "file" || len(component.Hashes) != 1 || component.Hashes[0].Algorithm != "SHA-256" || component.Hashes[0].Content != normalized {
				return errors.New("releasebuild: OCI CA SBOM binding mismatch")
			}
			found = true
		}
	}
	if !found {
		return errors.New("releasebuild: OCI CA SBOM component missing")
	}
	return verifyOCIImage(path, artifact.GetProduct(), artifact.GetArchitecture(), normalized)
}

func verifyOCIImage(path, product, architecture, caPin string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	archive := tar.NewReader(file)
	readMetadata := func(expected string) (*tar.Header, []byte, error) {
		header, err := archive.Next()
		if err != nil {
			return nil, nil, err
		}
		if header.Typeflag != tar.TypeReg || header.Size > 1<<20 || header.Size < 0 || (expected != "" && header.Name != expected) {
			return nil, nil, errors.New("releasebuild: invalid OCI metadata member")
		}
		data, err := io.ReadAll(archive)
		return header, data, err
	}
	_, layout, err := readMetadata("oci-layout")
	if err != nil {
		return err
	}
	var layoutVersion struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(layout, &layoutVersion); err != nil {
		return err
	}
	if layoutVersion.Version != "1.0.0" {
		return errors.New("releasebuild: OCI layout version mismatch")
	}
	_, indexJSON, err := readMetadata("index.json")
	if err != nil {
		return err
	}
	var index struct {
		SchemaVersion int               `json:"schemaVersion"`
		Manifests     []imageDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(indexJSON, &index); err != nil {
		return err
	}
	if index.SchemaVersion != 2 || len(index.Manifests) != 1 {
		return errors.New("releasebuild: OCI index mismatch")
	}
	configHeader, configJSON, err := readMetadata("")
	if err != nil {
		return err
	}
	manifestName, err := descriptorPath(index.Manifests[0], "application/vnd.oci.image.manifest.v1+json")
	if err != nil {
		return err
	}
	manifestHeader, manifestJSON, err := readMetadata(manifestName)
	if err != nil {
		return err
	}
	if err := checkDescriptor(index.Manifests[0], manifestHeader, manifestJSON); err != nil {
		return err
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		Config        imageDescriptor   `json:"config"`
		Layers        []imageDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != 2 || len(manifest.Layers) != 1 {
		return errors.New("releasebuild: OCI manifest mismatch")
	}
	configName, err := descriptorPath(manifest.Config, "application/vnd.oci.image.config.v1+json")
	if err != nil {
		return err
	}
	if configHeader.Name != configName {
		return errors.New("releasebuild: OCI config path mismatch")
	}
	if err := checkDescriptor(manifest.Config, configHeader, configJSON); err != nil {
		return err
	}
	if err := verifyOCIConfig(configJSON, product, architecture, manifest.Layers[0].Digest); err != nil {
		return err
	}
	if err := verifyOCILayer(archive, manifest.Layers[0], product, caPin); err != nil {
		return err
	}
	if _, err := archive.Next(); err != io.EOF {
		return errors.New("releasebuild: unexpected OCI archive member")
	}
	return nil
}

// verifyOCIConfig binds the image config to the product entrypoint, unprivileged
// user, explicit CA bundle and the single layer.
func verifyOCIConfig(configJSON []byte, product, architecture, layerDigest string) error {
	var config struct {
		Architecture, OS string
		Config           struct {
			User                 string
			Entrypoint, Env, Cmd []string
		}
		RootFS struct {
			Type    string
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return err
	}
	if config.Architecture != architecture || config.OS != "linux" || config.Config.User != "65532:65532" || !slices.Equal(config.Config.Entrypoint, []string{"/usr/bin/" + product}) || !slices.Equal(config.Config.Env, []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}) || config.RootFS.Type != "layers" || !slices.Equal(config.RootFS.DiffIDs, []string{layerDigest}) {
		return errors.New("releasebuild: OCI runtime/config binding mismatch")
	}
	if product == "lindmd" && !slices.Equal(config.Config.Cmd, []string{"serve"}) {
		return errors.New("releasebuild: OCI server command missing")
	}
	return nil
}

// verifyOCILayer streams the next archive member as the described layer: exactly
// the product binary and the pinned CA bundle, with the descriptor's digest.
func verifyOCILayer(archive *tar.Reader, descriptor imageDescriptor, product, caPin string) error {
	layerName, err := descriptorPath(descriptor, "application/vnd.oci.image.layer.v1.tar")
	if err != nil {
		return err
	}
	layerHeader, err := archive.Next()
	if err != nil {
		return err
	}
	if layerHeader.Name != layerName || layerHeader.Typeflag != tar.TypeReg || layerHeader.Size != descriptor.Size || layerHeader.Size > maxArtifact {
		return errors.New("releasebuild: OCI layer descriptor mismatch")
	}
	hash := sha256.New()
	stream := io.TeeReader(archive, hash)
	layer := tar.NewReader(stream)
	for _, entry := range []struct {
		name string
		mode int64
	}{{"usr/bin/" + product, 0555}, {"etc/ssl/certs/ca-certificates.crt", 0444}} {
		header, err := layer.Next()
		if err != nil {
			return err
		}
		if header.Name != entry.name || header.Typeflag != tar.TypeReg || header.Mode != entry.mode || header.Uid != 0 || header.Gid != 0 {
			return errors.New("releasebuild: OCI layer member mismatch")
		}
		if entry.mode == 0444 {
			if header.Size > 4<<20 {
				return errors.New("releasebuild: OCI CA bundle exceeds bound")
			}
			data, err := io.ReadAll(layer)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != caPin {
				return errors.New("releasebuild: actual OCI CA differs from SBOM/provenance")
			}
		}
	}
	if _, err := layer.Next(); err != io.EOF {
		return errors.New("releasebuild: unexpected OCI layer member")
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != descriptor.Digest {
		return errors.New("releasebuild: OCI layer digest mismatch")
	}
	return nil
}

func descriptorPath(descriptor imageDescriptor, mediaType string) (string, error) {
	if descriptor.MediaType != mediaType || len(descriptor.Digest) != 71 || descriptor.Digest[:7] != "sha256:" || descriptor.Size <= 0 {
		return "", errors.New("releasebuild: invalid OCI descriptor")
	}
	pin, err := normalizeSHA256(descriptor.Digest[7:])
	if err != nil || pin != descriptor.Digest[7:] {
		return "", errors.New("releasebuild: invalid OCI descriptor digest")
	}
	return "blobs/sha256/" + pin, nil
}
func checkDescriptor(descriptor imageDescriptor, header *tar.Header, data []byte) error {
	digest := sha256.Sum256(data)
	if descriptor.Size != header.Size || descriptor.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("releasebuild: OCI metadata digest mismatch")
	}
	return nil
}
