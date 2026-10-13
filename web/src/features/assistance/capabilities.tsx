import { useId } from "react";
import {
  AssistancePolicyMode,
  type AssistancePolicy,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";

export const capabilityFields = ["clipboard", "keyboard", "display", "messages"] as const;
export type CapabilityField = (typeof capabilityFields)[number];

export const capabilityLabels: Record<CapabilityField, string> = {
  clipboard: "Clipboard",
  keyboard: "Keyboard",
  display: "Displays",
  messages: "Messages",
};

export const capabilityPermissions: Record<CapabilityField, string> = {
  clipboard: "remote_assistance.clipboard",
  keyboard: "remote_assistance.keyboard",
  display: "remote_assistance.display",
  messages: "remote_assistance.message",
};

const limitedLabels: Record<CapabilityField, string> = {
  clipboard: "Send text only",
  keyboard: "Text only",
  display: "Current display only",
  messages: "One message at a time",
};
const onLabels: Record<CapabilityField, string> = {
  clipboard: "Send and read text",
  keyboard: "Text and physical keys",
  display: "Select shared displays",
  messages: "Sequential messages",
};

export function policyMode(policy: AssistancePolicy | undefined, field: CapabilityField) {
  const mode = policy?.[field];
  return mode === AssistancePolicyMode.LIMITED || mode === AssistancePolicyMode.ON
    ? mode
    : AssistancePolicyMode.OFF;
}

export function CapabilityFields({
  value,
  ceiling,
  disabled,
  manage = false,
  onChange,
}: {
  value: AssistancePolicy;
  ceiling?: AssistancePolicy;
  disabled: boolean;
  manage?: boolean;
  onChange: (field: CapabilityField, mode: AssistancePolicyMode) => void;
}) {
  const id = useId();
  const principal = usePrincipal();
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {capabilityFields.map((field) => {
        const allowed = manage || canPermission(principal, capabilityPermissions[field]);
        const maximum = policyMode(ceiling, field);
        const reason = !allowed
          ? "Your role does not allow this feature."
          : maximum === AssistancePolicyMode.OFF
            ? "This feature is off in the assistance policy."
            : "";
        return (
          <div key={field} className="grid gap-2">
            <Label htmlFor={`${id}-${field}`}>{capabilityLabels[field]}</Label>
            <SelectField
              id={`${id}-${field}`}
              value={policyMode(value, field)}
              disabled={
                disabled ||
                (policyMode(value, field) === AssistancePolicyMode.OFF &&
                  (!allowed || maximum === AssistancePolicyMode.OFF))
              }
              aria-describedby={reason ? `${id}-${field}-reason` : undefined}
              options={[
                { value: AssistancePolicyMode.OFF, label: "Off" },
                {
                  value: AssistancePolicyMode.LIMITED,
                  label: limitedLabels[field],
                  disabled: !allowed || maximum < AssistancePolicyMode.LIMITED,
                },
                {
                  value: AssistancePolicyMode.ON,
                  label: onLabels[field],
                  disabled: !allowed || maximum < AssistancePolicyMode.ON,
                },
              ]}
              onValueChange={(next) => onChange(field, Number(next) as AssistancePolicyMode)}
            />
            {reason ? (
              <p id={`${id}-${field}-reason`} className="text-sm text-muted-foreground">
                {reason}
              </p>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
