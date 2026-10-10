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
	"path/filepath"
	"time"
)

// OCI images contain the static executable and an explicitly supplied, pinned
// CA bundle recorded in provenance/SBOM. Ambient host roots are never copied.
func buildOCI(binary, caBundle, destination, product, arch string, epoch int64) (err error) {
	work, err := os.MkdirTemp(filepath.Dir(destination), "oci-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }()
	blobs := filepath.Join(work, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0700); err != nil {
		return err
	}
	layer := filepath.Join(work, "layer.tar")
	if err := tarFiles(layer, []tarInput{{source: binary, name: "usr/bin/" + product, mode: 0555}, {source: caBundle, name: "etc/ssl/certs/ca-certificates.crt", mode: 0444}}, epoch); err != nil {
		return err
	}
	layerHash, layerSize, err := digestFile(layer)
	if err != nil {
		return err
	}
	if err := os.Rename(layer, filepath.Join(blobs, layerHash)); err != nil {
		return err
	}
	runtimeConfig := map[string]any{"User": "65532:65532", "Entrypoint": []string{"/usr/bin/" + product}, "Env": []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, "WorkingDir": "/"}
	if product == "lindmd" {
		runtimeConfig["Cmd"] = []string{"serve"}
	}
	config := map[string]any{"architecture": arch, "os": "linux", "created": time.Unix(epoch, 0).UTC().Format(time.RFC3339), "config": runtimeConfig, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + layerHash}}}
	configHash, configSize, err := ociBlob(blobs, config)
	if err != nil {
		return err
	}
	manifest := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": ociDescriptor("application/vnd.oci.image.config.v1+json", configHash, configSize), "layers": []any{ociDescriptor("application/vnd.oci.image.layer.v1.tar", layerHash, layerSize)}}
	manifestHash, manifestSize, err := ociBlob(blobs, manifest)
	if err != nil {
		return err
	}
	descriptor := ociDescriptor("application/vnd.oci.image.manifest.v1+json", manifestHash, manifestSize)
	descriptor["platform"] = map[string]string{"architecture": arch, "os": "linux"}
	descriptor["annotations"] = map[string]string{"org.opencontainers.image.ref.name": product + ":" + arch}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{descriptor}})
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(work, "index.json"), index, 0600); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(work, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600); err != nil {
		return err
	}
	entries := []tarInput{{source: filepath.Join(work, "oci-layout"), name: "oci-layout", mode: 0644}, {source: filepath.Join(work, "index.json"), name: "index.json", mode: 0644}}
	for _, hash := range []string{configHash, manifestHash, layerHash} {
		entries = append(entries, tarInput{source: filepath.Join(blobs, hash), name: "blobs/sha256/" + hash, mode: 0644})
	}
	return tarFiles(destination, entries, epoch)
}

func ociDescriptor(media, hash string, size int64) map[string]any {
	return map[string]any{"mediaType": media, "digest": "sha256:" + hash, "size": size}
}
func ociBlob(directory string, value any) (string, int64, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	return hash, int64(len(data)), writeNew(filepath.Join(directory, hash), data, 0600)
}

type tarInput struct {
	source, name string
	mode         int64
}

func tarFiles(destination string, entries []tarInput, epoch int64) (err error) {
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	archive := tar.NewWriter(out)
	for _, entry := range entries {
		in, err := os.Open(entry.source)
		if err != nil {
			return err
		}
		info, err := in.Stat()
		if err != nil {
			_ = in.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxArtifact {
			_ = in.Close()
			return errors.New("releasebuild: invalid OCI member")
		}
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Size: info.Size(), Typeflag: tar.TypeReg, ModTime: time.Unix(epoch, 0), Format: tar.FormatUSTAR}
		if err := archive.WriteHeader(header); err != nil {
			_ = in.Close()
			return err
		}
		_, copyErr := io.CopyN(archive, in, info.Size())
		if err := errors.Join(copyErr, in.Close()); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return out.Sync()
}
