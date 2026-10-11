package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/orgapply"
)

// applyEngine is the command's test boundary; production always uses orgapply.
// In particular no browser account adapter is available through CLI credentials.
type applyEngine struct {
	plan  func(context.Context, adminv1connect.AdminServiceClient, *orgv1.Organization) (*orgapply.ChangePlan, error)
	apply func(context.Context, adminv1connect.AdminServiceClient, *orgapply.ChangePlan, orgapply.Options) (*orgapply.Result, error)
}

func (f *commandFlags) applyOrganization(ctx context.Context, client adminv1connect.AdminServiceClient, out io.Writer, format string, engine applyEngine) (resultErr error) {
	if f.file == "" {
		return errors.New("apply requires -f FILE")
	}
	if f.dryRun && f.secretsOut != "" {
		return errors.New("-secrets-out cannot be used with -dry-run")
	}
	data, err := readDocument(f.file)
	if err != nil {
		return errors.New("read organization file failed")
	}
	spec, err := orgapply.Decode(data)
	if err != nil {
		// Decoder errors can contain document values, including accidental secrets.
		return errors.New("organization file must be strict, valid Organization protobuf JSON")
	}
	plan, err := engine.plan(ctx, client, spec)
	if err != nil {
		return err
	}
	if f.dryRun {
		return printApplyOutcomes(out, plan.Outcomes, format)
	}
	for _, outcome := range plan.Outcomes {
		if outcome.Status == "created" && (outcome.Kind == "provisioning_token" || outcome.Kind == "enrollment_grant") && f.secretsOut == "" {
			return errors.New("apply would issue secrets; provide -secrets-out NEW_FILE")
		}
	}
	var secrets *os.File
	if f.secretsOut != "" {
		secrets, err = os.OpenFile(f.secretsOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("create secrets output failed; use a new file in a private directory")
		}
		defer func() { resultErr = errors.Join(resultErr, secrets.Close()) }()
	}
	result, applyErr := engine.apply(ctx, client, plan, orgapply.Options{})
	if result == nil {
		return applyErr
	}
	// Preserve successful issuance even if a later object failed. Never marshal
	// Result.Secrets to stdout, and never retry issuance after a write failure.
	if secrets != nil {
		if err := json.NewEncoder(secrets).Encode(result.Secrets); err != nil {
			return errors.Join(applyErr, errors.New("write secrets output failed; issued secrets may be unrecoverable; do not retry issuance"))
		}
		if err := secrets.Sync(); err != nil {
			return errors.Join(applyErr, errors.New("sync secrets output failed; issued secrets may be unrecoverable; do not retry issuance"))
		}
	}
	return errors.Join(applyErr, printApplyOutcomes(out, result.Outcomes, format))
}

func printApplyOutcomes(out io.Writer, outcomes []orgapply.Outcome, format string) error {
	if format == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(struct {
			Outcomes []orgapply.Outcome `json:"outcomes"`
		}{Outcomes: outcomes})
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "KIND\tNAME\tID\tSTATUS\tREASON"); err != nil {
		return err
	}
	for _, outcome := range outcomes {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", applyValue(outcome.Kind), applyValue(outcome.Name), applyValue(outcome.ID), applyValue(outcome.Status), applyValue(outcome.Detail)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func applyValue(value string) string { return terminalValue(protoreflect.ValueOfString(value)) }
