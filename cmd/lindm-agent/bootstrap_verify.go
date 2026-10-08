package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"lindm/internal/trust"
)

// verifyBootstrap is a public-document diagnostic, not enrollment or trust import.
// Provisioning must separately enforce root-owned state and trusted acquisition.
func verifyBootstrap(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("verify-bootstrap", flag.ContinueOnError)
	rootPath := flags.String("root", "", "authenticated execution-root protobuf JSON document")
	bundlePath := flags.String("bundle", "", "DSSE-signed bootstrap bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *rootPath == "" || *bundlePath == "" {
		return errors.New("verify-bootstrap requires -root FILE -bundle FILE")
	}
	root, err := readPublicDocument(*rootPath, 64<<10)
	if err != nil {
		return fmt.Errorf("read execution root: %w", err)
	}
	bundle, err := readPublicDocument(*bundlePath, 512<<10)
	if err != nil {
		return fmt.Errorf("read bootstrap bundle: %w", err)
	}
	authority, err := trust.New()
	if err != nil {
		return err
	}
	verified, err := authority.VerifyBootstrap(ctx, root, bundle, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "Verified bootstrap %s for deployment %s, execution root version %d.\nEnrollment: %s\nDevice: %s\nNo trust was imported and no device was enrolled.\n", verified.Bundle.GetBundleId(), verified.Bundle.GetDeploymentId(), verified.Root.GetVersion(), verified.Bundle.GetEnrollmentOrigin(), verified.Bundle.GetDeviceOrigin())
	return err
}

func readPublicDocument(path string, limit int64) (_ []byte, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("document must be a bounded regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("document exceeds size limit")
	}
	return content, nil
}
