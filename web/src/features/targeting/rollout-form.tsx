import { create } from "@bufbuild/protobuf";
import { PutRolloutRequestSchema } from "../../../gen/lindm/admin/v1/targeting_pb";
import { RolloutRingSchema } from "../../../gen/lindm/policy/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { CohortControl, NumberControl, ReasonControl, OptionalControls } from "./controls";
import { TargetMutation } from "./mutation";

function newStage(index: number) {
  return create(RolloutRingSchema, {
    name: `Stage-${index + 1}`,
    cumulativeBasisPoints: index === 0 ? 1000 : 10000,
    minimumCanaries: 1,
    minimumObserved: 1,
    soakSeconds: 3600,
    healthMaxAgeSeconds: 3600,
    manualPromotion: true,
  });
}

export function RolloutForm() {
  return (
    <TargetMutation
      title="Save staged rollout"
      formKey="rollout:new"
      schema={PutRolloutRequestSchema}
      initial={() =>
        create(PutRolloutRequestSchema, {
          requestId: newRequestId(),
          rollout: {
            rolloutId: newRequestId(),
            salt: crypto.getRandomValues(new Uint8Array(32)),
            rings: [newStage(0)],
          },
        })
      }
      send={(request, signal) => adminClient.putRollout(request, { signal })}
      fields={(request, change, disabled) => {
        const rollout = request.rollout;
        if (!rollout) return null;
        const stages = rollout.rings;
        const setStages = (rings: typeof stages) => {
          change(create(PutRolloutRequestSchema, { ...request, rollout: { ...rollout, rings } }));
        };
        return (
          <fieldset disabled={disabled} className="grid min-w-0 gap-4">
            <p className="text-sm text-muted-foreground">
              Define who enters each stage and the evidence needed to widen it. Saving does not
              activate device changes.
            </p>
            {stages.map((stage, index) => {
              function set(next: Partial<typeof stage>) {
                setStages(
                  stages.map((item, i) =>
                    i === index ? create(RolloutRingSchema, { ...stage, ...next }) : item,
                  ),
                );
              }
              return (
                <fieldset key={index} className="grid min-w-0 gap-4 border p-3">
                  <legend className="text-sm font-semibold">Stage {index + 1}</legend>
                  <label className="grid gap-1.5 text-sm">
                    Stage name
                    <Input
                      required
                      value={stage.name}
                      onChange={(event) => set({ name: event.target.value })}
                    />
                  </label>
                  <CohortControl
                    label={`Devices for stage ${index + 1}`}
                    value={stage.cohort}
                    disabled={disabled}
                    onChange={(cohort) => set({ cohort })}
                  />
                  <NumberControl
                    label="Cumulative device share (%)"
                    percent
                    value={stage.cumulativeBasisPoints}
                    onChange={(cumulativeBasisPoints) => set({ cumulativeBasisPoints })}
                  />
                  <div className="grid gap-3 sm:grid-cols-2">
                    <NumberControl
                      label="Minimum initial devices"
                      value={stage.minimumCanaries}
                      onChange={(minimumCanaries) => set({ minimumCanaries })}
                    />
                    <NumberControl
                      label="Minimum devices with observations"
                      value={stage.minimumObserved}
                      onChange={(minimumObserved) => set({ minimumObserved })}
                    />
                    <NumberControl
                      label="Observation period (seconds)"
                      value={stage.soakSeconds}
                      onChange={(soakSeconds) => set({ soakSeconds })}
                    />
                    <NumberControl
                      label="Maximum observation age (seconds)"
                      value={stage.healthMaxAgeSeconds}
                      onChange={(healthMaxAgeSeconds) => set({ healthMaxAgeSeconds })}
                    />
                  </div>
                  <OptionalControls title="Guardrails before widening">
                    <p className="text-sm text-muted-foreground">
                      Zero tolerates none. Old observations do not count as fresh evidence.
                    </p>
                    <NumberControl
                      label="Maximum failed devices (%)"
                      percent
                      value={stage.failureBasisPoints}
                      onChange={(failureBasisPoints) => set({ failureBasisPoints })}
                    />
                    <NumberControl
                      label="Maximum unknown devices (%)"
                      percent
                      value={stage.unknownBasisPoints}
                      onChange={(unknownBasisPoints) => set({ unknownBasisPoints })}
                    />
                    <NumberControl
                      label="Maximum unavailable devices (%)"
                      percent
                      value={stage.unavailableBasisPoints}
                      onChange={(unavailableBasisPoints) => set({ unavailableBasisPoints })}
                    />
                  </OptionalControls>
                  <label className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={stage.manualPromotion}
                      onChange={(event) => set({ manualPromotion: event.target.checked })}
                    />
                    Require an administrator to move to the next stage
                  </label>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-fit"
                    onClick={() => setStages(stages.filter((_, i) => i !== index))}
                  >
                    Remove stage {index + 1}
                  </Button>
                </fieldset>
              );
            })}
            <Button
              type="button"
              variant="outline"
              className="w-fit"
              onClick={() => setStages([...stages, newStage(stages.length)])}
            >
              Add stage
            </Button>
            <ReasonControl
              value={request.reason}
              onChange={(reason) => change(create(PutRolloutRequestSchema, { ...request, reason }))}
            />
          </fieldset>
        );
      }}
    />
  );
}
