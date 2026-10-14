// SPDX-License-Identifier: Apache-2.0

import { useId } from "react";
import {
  AssistancePolicyMode,
  type AssistancePolicy,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";

export const desktopFields = ["kdePlasma", "x11"] as const;
export type DesktopField = (typeof desktopFields)[number];

const desktopLabels: Record<DesktopField, string> = {
  kdePlasma: "KDE Plasma (Wayland)",
  x11: "X11 sessions",
};

export function desktopMode(policy: AssistancePolicy | undefined, field: DesktopField) {
  const mode = policy?.[field];
  return mode === AssistancePolicyMode.LIMITED || mode === AssistancePolicyMode.ON
    ? mode
    : AssistancePolicyMode.OFF;
}

// Desktop gates are device policy only: requests never choose a desktop, and
// each desktop admits only the features lindm has qualified on it.
export function DesktopPolicyFields({
  value,
  ceiling,
  disabled,
  onChange,
}: {
  value: AssistancePolicy;
  ceiling?: AssistancePolicy;
  disabled: boolean;
  onChange: (field: DesktopField, mode: AssistancePolicyMode) => void;
}) {
  const id = useId();
  return (
    <fieldset className="grid gap-3 border p-3" disabled={disabled}>
      <legend className="px-1 font-semibold">Other desktops</legend>
      <p className="text-sm text-muted-foreground">
        GNOME and COSMIC on Wayland don&apos;t need this setting. On the desktops below, support
        works only when allowed here, and only with the features tested on that desktop.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        {desktopFields.map((field) => {
          const maximum = desktopMode(ceiling, field);
          const current = desktopMode(value, field);
          return (
            <div key={field} className="grid gap-2">
              <Label htmlFor={`${id}-${field}`}>{desktopLabels[field]}</Label>
              <SelectField
                id={`${id}-${field}`}
                value={current}
                disabled={
                  current === AssistancePolicyMode.OFF && maximum === AssistancePolicyMode.OFF
                }
                aria-describedby={
                  maximum === AssistancePolicyMode.OFF ? `${id}-${field}-reason` : undefined
                }
                options={[
                  { value: AssistancePolicyMode.OFF, label: "Off" },
                  {
                    value: AssistancePolicyMode.LIMITED,
                    label: "View only",
                    disabled: maximum < AssistancePolicyMode.LIMITED,
                  },
                  {
                    value: AssistancePolicyMode.ON,
                    label: "View and control",
                    disabled: maximum < AssistancePolicyMode.ON,
                  },
                ]}
                onValueChange={(next) => onChange(field, Number(next) as AssistancePolicyMode)}
              />
              {maximum === AssistancePolicyMode.OFF ? (
                <p id={`${id}-${field}-reason`} className="text-sm text-muted-foreground">
                  This desktop is off in the server&apos;s assistance policy.
                </p>
              ) : null}
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}
