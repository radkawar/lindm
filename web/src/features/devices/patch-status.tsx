import {
  PatchRunPhase,
  PatchRunResult,
  PatchRunTool,
  PatchRunTrigger,
  type PatchRunSummary,
  type PatchStatusObservation,
} from "../../../gen/lindm/agent/v1/os_update_pb";
import { OSUpdateBackend } from "../../../gen/lindm/resource/v1/observations_pb";
import { UpdateSelection } from "../../../gen/lindm/resource/v1/software_pb";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Fact, ObservedTime } from "./observations";

const backendLabels: Record<OSUpdateBackend, string> = {
  [OSUpdateBackend.OS_UPDATE_BACKEND_UNSPECIFIED]: "Not reported",
  [OSUpdateBackend.OS_UPDATE_BACKEND_APT_UNATTENDED_UPGRADES]: "APT unattended-upgrades",
  [OSUpdateBackend.OS_UPDATE_BACKEND_DNF5_AUTOMATIC]: "DNF5 automatic",
  [OSUpdateBackend.OS_UPDATE_BACKEND_DNF4_AUTOMATIC]: "dnf-automatic",
  [OSUpdateBackend.OS_UPDATE_BACKEND_PACMAN]: "pacman whole-system upgrade",
  [OSUpdateBackend.OS_UPDATE_BACKEND_ZYPPER]: "zypper distribution upgrade",
};

const triggerLabels: Record<PatchRunTrigger, string> = {
  [PatchRunTrigger.UNSPECIFIED]: "Not reported",
  [PatchRunTrigger.MAINTENANCE_WINDOW]: "Maintenance window",
  [PatchRunTrigger.PATCH_NOW]: "Patch now",
};

const resultLabels: Record<PatchRunResult, [string, StatusTone]> = {
  [PatchRunResult.UNSPECIFIED]: ["Not reported", "neutral"],
  [PatchRunResult.SUCCEEDED]: ["Succeeded", "success"],
  [PatchRunResult.FAILED]: ["Failed", "destructive"],
  [PatchRunResult.SKIPPED_OUTSIDE_WINDOW]: ["Skipped outside window", "neutral"],
  [PatchRunResult.DEFERRED]: ["Deferred", "info"],
  [PatchRunResult.REJECTED]: ["Rejected", "warning"],
};

const selectionLabels: Record<UpdateSelection, string> = {
  [UpdateSelection.UNSPECIFIED]: "Not reported",
  [UpdateSelection.SECURITY]: "Security updates",
  [UpdateSelection.ALL]: "All updates",
};

const toolLabels: Record<PatchRunTool, string> = {
  [PatchRunTool.UNSPECIFIED]: "Not reported",
  [PatchRunTool.APT_GET]: "apt-get",
  [PatchRunTool.UNATTENDED_UPGRADE]: "unattended-upgrade",
  [PatchRunTool.NEEDRESTART]: "needrestart",
  [PatchRunTool.DNF5]: "dnf5",
  [PatchRunTool.DNF]: "dnf",
  [PatchRunTool.DNF_AUTOMATIC]: "dnf-automatic",
  [PatchRunTool.LOGIND]: "systemd-logind",
  [PatchRunTool.LINDM_AGENT]: "lindm-agent",
  [PatchRunTool.PACMAN]: "pacman",
  [PatchRunTool.ZYPPER]: "zypper",
  [PatchRunTool.SNAPPER]: "snapper",
  [PatchRunTool.UPDATE_NOTIFIER]: "update-notifier",
};

const phaseLabels: Record<PatchRunPhase, string> = {
  [PatchRunPhase.UNSPECIFIED]: "Not reported",
  [PatchRunPhase.VALIDATION]: "Validation",
  [PatchRunPhase.REFRESH]: "Metadata refresh",
  [PatchRunPhase.LIST]: "Pending update listing",
  [PatchRunPhase.INSTALL]: "Installation",
  [PatchRunPhase.RESTART_SERVICES]: "Service restarts",
  [PatchRunPhase.REBOOT_CHECK]: "Reboot check",
  [PatchRunPhase.REBOOT_SCHEDULE]: "Reboot scheduling",
};

function LastRun({ run }: { run: PatchRunSummary | undefined }) {
  if (!run) {
    return (
      <p className="text-sm text-muted-foreground">
        The device has not reported a lindm patch run.
      </p>
    );
  }
  const [result, tone] = resultLabels[run.result] ?? [`Unknown result ${run.result}`, "warning"];
  const diagnostic = run.diagnostic;
  return (
    <section className="grid gap-3" aria-label="Last patch run">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium">Last run</h3>
        <StatusBadge status={tone}>{result}</StatusBadge>
      </div>
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Fact label="Trigger">{triggerLabels[run.trigger] ?? "Unknown trigger"}</Fact>
        <Fact label="Action ID">
          {run.actionId ? (
            <span className="break-all font-mono text-xs">{run.actionId}</span>
          ) : (
            "None (maintenance window)"
          )}
        </Fact>
        <Fact label="Selection">{selectionLabels[run.selection] ?? "Unknown selection"}</Fact>
        <Fact label="Started">
          <ObservedTime value={run.startedAt} />
        </Fact>
        <Fact label="Finished">
          <ObservedTime value={run.finishedAt} />
        </Fact>
        <Fact label="Updated packages">{run.updatedPackages.toLocaleString()}</Fact>
        <Fact label="Deferred packages">{run.deferredPackages.toLocaleString()}</Fact>
        <Fact label="Reboot required after run">{run.rebootRequired ? "Yes" : "No"}</Fact>
        <Fact label="Reboot scheduled for">
          {run.rebootScheduledFor ? <ObservedTime value={run.rebootScheduledFor} /> : "None"}
        </Fact>
        <Fact label="Reboot reason">
          {run.rebootReason ? (
            <span className="font-mono text-xs">{run.rebootReason}</span>
          ) : (
            "None reported"
          )}
        </Fact>
        <Fact label="Notified sessions">{run.notifiedSessions.toLocaleString()}</Fact>
      </dl>
      {diagnostic ? (
        <section className="grid gap-2 border p-3" aria-label="Native diagnostic">
          <h4 className="text-sm font-medium">Native diagnostic</h4>
          <dl className="grid gap-4 sm:grid-cols-3">
            <Fact label="Tool">{toolLabels[diagnostic.tool] ?? "Unknown tool"}</Fact>
            <Fact label="Phase">{phaseLabels[diagnostic.phase] ?? "Unknown phase"}</Fact>
            <Fact label="Exit code">
              {diagnostic.exitCode < 0 ? "No exit status" : diagnostic.exitCode}
            </Fact>
          </dl>
          {diagnostic.errorLines.length ? (
            <pre className="overflow-x-auto whitespace-pre-wrap break-words bg-muted p-2 font-mono text-xs">
              {/* Native output is verbatim except invisible, formatting and
                  line-breaking characters, which render as escapes. */}
              {diagnostic.errorLines
                .map((line) =>
                  line.replace(
                    /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/gu,
                    (character) => `\\u{${character.codePointAt(0)!.toString(16)}}`,
                  ),
                )
                .join("\n")}
            </pre>
          ) : (
            <p className="text-sm text-muted-foreground">No native error lines reported.</p>
          )}
          {diagnostic.truncated ? (
            <p className="text-xs text-muted-foreground">The device truncated native output.</p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}

export function DevicePatchStatus({ status }: { status: PatchStatusObservation | undefined }) {
  const available = status?.available === true;
  const unknown = "Unknown";
  return (
    <Card>
      <CardHeader>
        <CardTitle>Patch status</CardTitle>
        <CardDescription>
          The device computes patch status offline from its package cache. This report does not
          prove installation.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-6">
        {!status ? (
          <p className="text-muted-foreground">
            Patch status unknown. The latest report contains none.
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge
                status={
                  !available
                    ? "neutral"
                    : status.pendingSecurityUpdates > 0
                      ? "destructive"
                      : status.rebootRequired
                        ? "warning"
                        : "success"
                }
              >
                {!available
                  ? "Unknown"
                  : status.pendingSecurityUpdates > 0
                    ? "Security updates pending"
                    : status.rebootRequired
                      ? "Reboot required"
                      : "Patched"}
              </StatusBadge>
              {!available ? (
                <span className="break-all font-mono text-xs text-muted-foreground">
                  {status.reason || "No reason reported"}
                </span>
              ) : null}
            </div>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Computed">
                <ObservedTime value={status.observedAt} />
              </Fact>
              <Fact label="Backend">{available ? backendLabels[status.backend] : unknown}</Fact>
              <Fact label="Pending security updates">
                {available ? status.pendingSecurityUpdates.toLocaleString() : unknown}
              </Fact>
              <Fact label="Pending updates">
                {available ? status.pendingUpdates.toLocaleString() : unknown}
              </Fact>
              <Fact label="Deferred updates">
                {available ? status.deferredUpdates.toLocaleString() : unknown}
              </Fact>
              <Fact label="Reboot required">
                {available ? (status.rebootRequired ? "Yes" : "No") : unknown}
              </Fact>
              <Fact label="Scheduled reboot">
                {status.rebootScheduledFor ? (
                  <ObservedTime value={status.rebootScheduledFor} />
                ) : available ? (
                  "None"
                ) : (
                  unknown
                )}
              </Fact>
              {status.rebootDeadline && (
                <>
                  <Fact label="Restart deadline">
                    <ObservedTime value={status.rebootDeadline} />
                  </Fact>
                  <Fact label="Employee deferrals used">
                    {status.rebootDeferralsUsed.toLocaleString()}
                  </Fact>
                </>
              )}
              <Fact label="Metadata refreshed">
                {status.metadataRefreshedAt ? (
                  <ObservedTime value={status.metadataRefreshedAt} />
                ) : (
                  unknown
                )}
              </Fact>
              <Fact label="Last successful update">
                {status.lastSuccessfulUpdate ? (
                  <ObservedTime value={status.lastSuccessfulUpdate} />
                ) : (
                  "None recorded"
                )}
              </Fact>
              <Fact label="Update policy installed">
                {available ? (status.policyInstalled ? "Yes" : "No") : unknown}
              </Fact>
            </dl>
            <LastRun run={status.lastRun} />
          </>
        )}
      </CardContent>
    </Card>
  );
}
