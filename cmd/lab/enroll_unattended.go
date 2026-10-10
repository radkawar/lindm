package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"lindm/internal/vmlab"
)

func runVMEnrollUnattended(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm enroll-unattended", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "signed Ubuntu 24.04 or Fedora 44 cloud image manifest")
	record := flags.String("record", "", "new nonsecret evidence file, written only after owned cleanup succeeds")
	var options vmlab.VMUnattendedOptions
	flags.StringVar(&options.Repository, "repo", ".", "checkout with protected development trust and running PostgreSQL")
	flags.StringVar(&options.CacheDir, "cache", ".cache/lab/images", "verified cloud image cache")
	flags.StringVar(&options.WorkDir, "work", "", "parent of private disposable run directories")
	flags.StringVar(&options.LindmdBinary, "lindmd", "", "prebuilt current lindmd executable")
	flags.StringVar(&options.LabBinary, "lab-binary", "", "prebuilt matching Linux amd64 lab probe executable")
	flags.BoolVar(&options.ApprovalRequired, "approval-required", false, "require independent approval for both native enrollments and prove preapproval denial")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest is required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	result, err := vmlab.EnrollUnattendedVM(ctx, manifest, options)
	if err != nil {
		return err
	}
	return writeLabEvidence(stdout, *record, result)
}
