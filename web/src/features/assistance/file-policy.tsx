// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useId } from "react";
import {
  AssistanceFilePolicySchema,
  type AssistanceFilePolicy,
} from "../../../gen/lindm/agent/v1/assistance_files_pb";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function FileLimitsSummary({ policy }: { policy?: AssistanceFilePolicy }) {
  return policy ? (
    <p className="text-sm text-muted-foreground">
      Up to {Number(policy.maxFileBytes).toLocaleString()} bytes per file and{" "}
      {Number(policy.maxSessionBytes).toLocaleString()} bytes per session. Allowed extensions:{" "}
      {policy.allowedExtensions.join(", ")}.
    </p>
  ) : (
    <p className="text-sm text-muted-foreground">
      File limits are unavailable. Ask your server admin to configure them.
    </p>
  );
}

export function FilePolicyFields({
  value,
  ceiling,
  disabled,
  onChange,
}: {
  value?: AssistanceFilePolicy;
  ceiling?: AssistanceFilePolicy;
  disabled: boolean;
  onChange: (value: AssistanceFilePolicy) => void;
}) {
  const id = useId();
  const current = value ?? create(AssistanceFilePolicySchema);
  return (
    <fieldset className="grid gap-3 border p-3" disabled={disabled}>
      <legend className="px-1 font-semibold">File limits</legend>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-file`}>Maximum bytes per file</Label>
          <Input
            data-freeform="numeric byte limit"
            id={`${id}-file`}
            type="number"
            min={1}
            max={Number(ceiling?.maxFileBytes ?? 16777216n)}
            step={1}
            value={String(current.maxFileBytes)}
            onChange={(event) => {
              if (/^\d*$/.test(event.target.value))
                onChange(
                  create(AssistanceFilePolicySchema, {
                    ...current,
                    maxFileBytes: BigInt(event.target.value || "0"),
                  }),
                );
            }}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-session`}>Maximum bytes per session</Label>
          <Input
            data-freeform="numeric byte limit"
            id={`${id}-session`}
            type="number"
            min={1}
            max={Number(ceiling?.maxSessionBytes ?? 67108864n)}
            step={1}
            value={String(current.maxSessionBytes)}
            onChange={(event) => {
              if (/^\d*$/.test(event.target.value))
                onChange(
                  create(AssistanceFilePolicySchema, {
                    ...current,
                    maxSessionBytes: BigInt(event.target.value || "0"),
                  }),
                );
            }}
          />
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-types`}>Allowed content types (comma separated)</Label>
        <Input
          data-freeform="content types the organization allows"
          id={`${id}-types`}
          value={current.allowedMimeTypes.join(",")}
          maxLength={1552}
          onChange={(event) =>
            onChange(
              create(AssistanceFilePolicySchema, {
                ...current,
                allowedMimeTypes: event.target.value.split(",").map((part) => part.trim()),
              }),
            )
          }
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-extensions`}>Allowed extensions (comma separated)</Label>
        <Input
          data-freeform="file extensions the organization allows"
          id={`${id}-extensions`}
          value={current.allowedExtensions.join(",")}
          maxLength={576}
          onChange={(event) =>
            onChange(
              create(AssistanceFilePolicySchema, {
                ...current,
                allowedExtensions: event.target.value.split(",").map((part) => part.trim()),
              }),
            )
          }
        />
      </div>
      <details className="text-sm">
        <summary className="cursor-pointer">File policy details</summary>
        <p className="mt-2">
          The actual content type and extension must both be allowed. Supported content types are
          text/plain, application/pdf, image/png and image/jpeg. Each file requires local approval
          or selection. Interrupted transfers still use the session allowance, with at most 32
          transfers per session.
        </p>
        <FileLimitsSummary policy={ceiling} />
        {ceiling ? <p>Allowed content types: {ceiling.allowedMimeTypes.join(", ")}.</p> : null}
      </details>
    </fieldset>
  );
}
