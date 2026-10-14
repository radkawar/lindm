// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useId } from "react";
import {
  AssistanceReconnectPolicySchema,
  AssistanceRecordingPolicySchema,
  type AssistanceReconnectPolicy,
  type AssistanceRecordingPolicy,
} from "../../../gen/lindm/agent/v1/assistance_recording_pb";
import {
  AssistanceUnattendedPolicySchema,
  type AssistanceUnattendedPolicy,
} from "../../../gen/lindm/agent/v1/assistance_unattended_pb";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const MIB = 1024 * 1024;

export function ReconnectLimitsSummary({ policy }: { policy?: AssistanceReconnectPolicy }) {
  return policy ? (
    <p className="text-sm text-muted-foreground">
      After a sign-out, restart or lock, a new request can follow for up to{" "}
      {Math.max(1, Math.floor(policy.windowSeconds / 60))} minutes, at most {policy.maxReconnects}{" "}
      times. The user must accept every new request.
    </p>
  ) : (
    <p className="text-sm text-muted-foreground">
      Reconnect limits are unavailable. Ask your server admin to configure them.
    </p>
  );
}

export function RecordingLimitsSummary({ policy }: { policy?: AssistanceRecordingPolicy }) {
  return policy ? (
    <p className="text-sm text-muted-foreground">
      Recordings are encrypted on the device, kept for {policy.retentionDays} days and limited to{" "}
      {Math.floor(Number(policy.maxBytes) / MIB)} MiB. The user is told before and during recording.
    </p>
  ) : (
    <p className="text-sm text-muted-foreground">
      Recording limits are unavailable. Ask your server admin to configure them.
    </p>
  );
}

function wholeNumber(value: string): number | null {
  return /^\d*$/.test(value) ? Number(value || "0") : null;
}

export function ReconnectPolicyFields({
  value,
  ceiling,
  disabled,
  onChange,
}: {
  value?: AssistanceReconnectPolicy;
  ceiling?: AssistanceReconnectPolicy;
  disabled: boolean;
  onChange: (value: AssistanceReconnectPolicy) => void;
}) {
  const id = useId();
  const current = value ?? create(AssistanceReconnectPolicySchema);
  return (
    <fieldset className="grid gap-3 border p-3" disabled={disabled}>
      <legend className="px-1 font-semibold">Reconnect limits</legend>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-window`}>Window after each sign-out or restart (minutes)</Label>
          <Input
            data-freeform="numeric time limit"
            id={`${id}-window`}
            type="number"
            min={1}
            max={Math.floor((ceiling?.windowSeconds ?? 14400) / 60)}
            step={1}
            value={String(Math.floor(current.windowSeconds / 60))}
            onChange={(event) => {
              const minutes = wholeNumber(event.target.value);
              if (minutes !== null)
                onChange(
                  create(AssistanceReconnectPolicySchema, {
                    ...current,
                    windowSeconds: minutes * 60,
                  }),
                );
            }}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-count`}>Maximum new requests per approved session</Label>
          <Input
            data-freeform="numeric count limit"
            id={`${id}-count`}
            type="number"
            min={1}
            max={ceiling?.maxReconnects ?? 8}
            step={1}
            value={String(current.maxReconnects)}
            onChange={(event) => {
              const count = wholeNumber(event.target.value);
              if (count !== null)
                onChange(
                  create(AssistanceReconnectPolicySchema, { ...current, maxReconnects: count }),
                );
            }}
          />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">
        Only workflow details are remembered. Screen sharing, control and every other permission
        need the user&apos;s fresh consent after each sign-in.
      </p>
    </fieldset>
  );
}

export function RecordingPolicyFields({
  value,
  ceiling,
  disabled,
  onChange,
}: {
  value?: AssistanceRecordingPolicy;
  ceiling?: AssistanceRecordingPolicy;
  disabled: boolean;
  onChange: (value: AssistanceRecordingPolicy) => void;
}) {
  const id = useId();
  const current = value ?? create(AssistanceRecordingPolicySchema);
  return (
    <fieldset className="grid gap-3 border p-3" disabled={disabled}>
      <legend className="px-1 font-semibold">Recording limits</legend>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-retention`}>Keep recordings for (days)</Label>
          <Input
            data-freeform="numeric retention period"
            id={`${id}-retention`}
            type="number"
            min={1}
            max={ceiling?.retentionDays ?? 365}
            step={1}
            value={String(current.retentionDays)}
            onChange={(event) => {
              const days = wholeNumber(event.target.value);
              if (days !== null)
                onChange(
                  create(AssistanceRecordingPolicySchema, { ...current, retentionDays: days }),
                );
            }}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-size`}>Maximum size per recording (MiB)</Label>
          <Input
            data-freeform="numeric size limit"
            id={`${id}-size`}
            type="number"
            min={1}
            max={Math.floor(Number(ceiling?.maxBytes ?? 1073741824n) / MIB)}
            step={1}
            value={String(Math.floor(Number(current.maxBytes) / MIB))}
            onChange={(event) => {
              const mebibytes = wholeNumber(event.target.value);
              if (mebibytes !== null)
                onChange(
                  create(AssistanceRecordingPolicySchema, {
                    ...current,
                    maxBytes: BigInt(mebibytes) * BigInt(MIB),
                  }),
                );
            }}
          />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">
        &quot;User may choose recording&quot; asks the user each time. &quot;Recording
        required&quot; lets an admin require it for a session: the session does not start, and
        stops, if recording or its notice is unavailable.
      </p>
    </fieldset>
  );
}

export function UnattendedLimitsSummary({ policy }: { policy?: AssistanceUnattendedPolicy }) {
  return policy ? (
    <p className="text-sm text-muted-foreground">
      A second person must approve each access period of up to{" "}
      {Math.max(1, Math.floor(policy.maxApprovalSeconds / 3600))} hours. Each connection lasts at
      most {Math.max(1, Math.floor(policy.maxSessionSeconds / 60))} minutes, and the user&apos;s
      opt-in expires after {policy.maxEnrollmentDays} days.
    </p>
  ) : (
    <p className="text-sm text-muted-foreground">
      Unattended limits are unavailable. Ask your server admin to configure them.
    </p>
  );
}

export function UnattendedPolicyFields({
  value,
  ceiling,
  disabled,
  onChange,
}: {
  value?: AssistanceUnattendedPolicy;
  ceiling?: AssistanceUnattendedPolicy;
  disabled: boolean;
  onChange: (value: AssistanceUnattendedPolicy) => void;
}) {
  const id = useId();
  const current = value ?? create(AssistanceUnattendedPolicySchema);
  return (
    <fieldset className="grid gap-3 border p-3" disabled={disabled}>
      <legend className="px-1 font-semibold">Unattended limits</legend>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-approval`}>Longest approved period (hours)</Label>
          <Input
            data-freeform="numeric time limit"
            id={`${id}-approval`}
            type="number"
            min={1}
            max={Math.floor((ceiling?.maxApprovalSeconds ?? 2592000) / 3600)}
            step={1}
            value={String(Math.floor(current.maxApprovalSeconds / 3600))}
            onChange={(event) => {
              const hours = wholeNumber(event.target.value);
              if (hours !== null)
                onChange(
                  create(AssistanceUnattendedPolicySchema, {
                    ...current,
                    maxApprovalSeconds: hours * 3600,
                  }),
                );
            }}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-enrollment`}>User opt-in lasts (days)</Label>
          <Input
            data-freeform="numeric time limit"
            id={`${id}-enrollment`}
            type="number"
            min={1}
            max={ceiling?.maxEnrollmentDays ?? 90}
            step={1}
            value={String(current.maxEnrollmentDays)}
            onChange={(event) => {
              const days = wholeNumber(event.target.value);
              if (days !== null)
                onChange(
                  create(AssistanceUnattendedPolicySchema, { ...current, maxEnrollmentDays: days }),
                );
            }}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-session`}>Longest connection (minutes)</Label>
          <Input
            data-freeform="numeric time limit"
            id={`${id}-session`}
            type="number"
            min={1}
            max={Math.floor((ceiling?.maxSessionSeconds ?? 1800) / 60)}
            step={1}
            value={String(Math.floor(current.maxSessionSeconds / 60))}
            onChange={(event) => {
              const minutes = wholeNumber(event.target.value);
              if (minutes !== null)
                onChange(
                  create(AssistanceUnattendedPolicySchema, {
                    ...current,
                    maxSessionSeconds: minutes * 60,
                  }),
                );
            }}
          />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">
        Unattended access reaches only a user who opted in on the device, only while their session
        is unlocked, and always shows a banner with Stop.
      </p>
    </fieldset>
  );
}
