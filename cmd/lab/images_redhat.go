//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/redhatimages"
	"lindm/internal/vmlab"
)

func runRedHatImages(ctx context.Context, args []string, stdout, stderr io.Writer) (err error) {
	if len(args) > 0 && (args[0] == "inventory" || args[0] == "cleanup") {
		return runRedHatRegistrationCommand(ctx, args[0], args[1:], stdout, stderr)
	}
	if len(args) == 0 || (args[0] != "discover" && args[0] != "fetch") {
		return errors.New("usage: lab images redhat {discover|fetch} -version MINOR -token-file FILE [-cache DIR] [-manifest NEW_FILE]; lab images redhat inventory -token-file FILE; lab images redhat cleanup -token-file FILE -confirm-delete-lab-registrations [-legacy-consumer-uuid UUID]; explicit supported RHEL minors include 9.8 and 10.2; fetch requires a new manifest file; offline checking uses lab images verify")
	}
	flags := flag.NewFlagSet("images redhat "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.String("version", "", "explicit supported RHEL 9 or 10 minor (for example 9.8 or 10.2), x86_64 KVM qcow2 only")
	token := flags.String("token-file", "", "current-user-owned mode-0600 Red Hat offline-token file; never pass a token value")
	cache := flags.String("cache", ".cache/lab/images", "dedicated digest-addressed image cache")
	manifestPath := flags.String("manifest", "", "new mode-0600 protobuf JSON manifest (required for fetch)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *version == "" || *token == "" {
		return errors.New("images redhat requires -version and -token-file, without positional arguments")
	}
	if (args[0] == "fetch") != (*manifestPath != "") {
		return errors.New("-manifest NEW_FILE is required only for images redhat fetch")
	}
	if *manifestPath != "" {
		if _, err := os.Lstat(*manifestPath); !errors.Is(err, os.ErrNotExist) {
			return errors.New("manifest destination must not already exist")
		}
		info, err := os.Stat(filepath.Dir(*manifestPath))
		if err != nil || !info.IsDir() {
			return errors.New("manifest parent must be an existing directory")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	client, err := redhatimages.New(ctx, *token)
	if err != nil {
		return err
	}
	defer client.Close()
	image, err := client.Discover(ctx, *version)
	if err != nil {
		return err
	}
	if args[0] == "discover" {
		_, err = fmt.Fprintf(stdout, "filename %s\nsha256 %s\npublished %s\nmetadata %s\nentitled %t\ntrust authenticated Red Hat HTTPS checksum; no detached vendor signature\n", image.Filename, image.SHA256, image.Published.Format(time.RFC3339Nano), image.MetadataURL(), image.Entitled)
		return err
	}
	staging, err := os.MkdirTemp("", "lindm-redhat-acquire-*")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	imagePath, receipt, err := client.Download(ctx, image, staging)
	if err != nil {
		return err
	}
	manifest := &labv1.ImageManifest{
		Id:           "rhel-" + image.Version + "-kvm-x86-64",
		Distribution: "rhel", Version: image.Version, Architecture: "x86_64", Edition: "KVM Guest Image",
		Release: image.Published.Format(time.RFC3339Nano), ImageFilename: image.Filename,
		ImageUrl: image.DownloadURL(), ChecksumUrl: image.MetadataURL(), Sha256: image.SHA256,
		ImageSizeBytes: receipt.ImageSizeBytes, ChecksumMode: labv1.ChecksumMode_CHECKSUM_MODE_VENDOR_AUTHENTICATED,
		ReleaseProvenanceUrl: image.MetadataURL(),
	}
	receiptBytes, err := protojson.Marshal(receipt)
	if err != nil {
		return err
	}
	verified, err := vmlab.ImportVendorImage(ctx, manifest, *cache, imagePath, receiptBytes)
	if err != nil {
		return err
	}
	if err := writeRedHatManifest(*manifestPath, manifest); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %s\nsha256 %s\nbytes %d\ntrust authenticated Red Hat HTTPS checksum; no detached vendor signature\nmanifest %q\nimage %q\n", manifest.Id, verified.SHA256, verified.Size, *manifestPath, verified.Path)
	return err
}

func writeRedHatManifest(path string, manifest *labv1.ImageManifest) (err error) {
	data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(manifest)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			err = errors.Join(err, os.Remove(path))
		}
	}()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

func runRedHatRegistrationCommand(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("images redhat "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	token := flags.String("token-file", "", "current-user-owned mode-0600 Red Hat offline-token file")
	var confirmed bool
	var legacyUUID string
	if command == "cleanup" {
		flags.BoolVar(&confirmed, "confirm-delete-lab-registrations", false, "confirm all lab lanes are stopped and delete only exact laboratory systems and activation keys")
		flags.StringVar(&legacyUUID, "legacy-consumer-uuid", "", "optional canonical consumer UUID independently established as a legacy lab orphan; never infer ownership from default hostname")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *token == "" || (command == "cleanup" && !confirmed) {
		return errors.New("registration inventory requires -token-file FILE; cleanup additionally requires -confirm-delete-lab-registrations after all lab lanes stop")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	client, err := redhatimages.New(ctx, *token)
	if err != nil {
		return err
	}
	defer client.Close()
	if command == "inventory" {
		systems, err := client.InventorySystems(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(systems)
	}
	result, cleanupErr := client.CleanupRegistrations(ctx, confirmed, legacyUUID)
	return errors.Join(cleanupErr, json.NewEncoder(stdout).Encode(result))
}
