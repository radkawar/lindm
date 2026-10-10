import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { AgentUpdateStatus } from "../../../gen/lindm/agent/v1/update_pb";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Fact, ObservedTime } from "./observations";

export function DeviceAgentUpdate({
  status,
  receivedAt,
}: {
  status: AgentUpdateStatus | undefined;
  receivedAt: Timestamp | undefined;
}) {
  const diagnostic = status?.nativeDiagnostic;
  const errorLines = diagnostic?.errorLines.slice(-8).map((line) => line.slice(0, 512)) ?? [];
  const truncated =
    diagnostic?.truncated ||
    (diagnostic !== undefined &&
      (diagnostic.errorLines.length > 8 ||
        diagnostic.errorLines.slice(-8).some((line) => line.length > 512)));

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Agent self-update history</CardTitle>
        <CardDescription>
          Historical device-reported diagnostics, not proof of the currently installed version,
          current package health, or verified update success. A missing native diagnostic does not
          mean an update succeeded.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!status ? (
          <p className="text-sm text-muted-foreground">Unknown: no self-update report received.</p>
        ) : (
          <>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Reported update opt-in">{status.enabled ? "Enabled" : "Disabled"}</Fact>
              <Fact label="Historical version">{status.version || "Not reported"}</Fact>
              <Fact label="Transaction ID">
                <span className="break-all font-mono">
                  {status.transactionId || "Not reported"}
                </span>
              </Fact>
              <Fact label="Reported phase">{status.phase || "Unknown"}</Fact>
              <Fact label="Last reported outcome">{status.lastOutcome || "Unknown"}</Fact>
              <Fact label="Device observation time">
                <ObservedTime value={status.observedAt} />
              </Fact>
              <Fact label="Attempt started">
                <ObservedTime value={status.attemptStartedAt} />
              </Fact>
              <Fact label="Attempt finished">
                <ObservedTime value={status.attemptFinishedAt} />
              </Fact>
              <Fact label="Last metadata observation">
                <ObservedTime value={status.lastMetadataAt} />
              </Fact>
              <Fact label="Reported reason">{status.reason || "Not reported"}</Fact>
            </dl>
            {diagnostic ? (
              <section className="space-y-3" aria-label="Historical native update failure">
                <h4 className="text-sm font-medium">Historical native update failure</h4>
                <dl className="grid gap-4 sm:grid-cols-3">
                  <Fact label="Native manager">{diagnostic.manager || "Unknown"}</Fact>
                  <Fact label="Failed operation phase">{diagnostic.phase || "Unknown"}</Fact>
                  <Fact label="Exit code">
                    {diagnostic.exitCode === -1
                      ? "Unavailable (non-exit error)"
                      : diagnostic.exitCode}
                  </Fact>
                </dl>
                {errorLines.length ? (
                  <div>
                    <p className="mb-2 text-sm text-muted-foreground">Final native error lines</p>
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted p-3 text-xs">
                      {errorLines.join("\n")}
                    </pre>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No native error lines reported.</p>
                )}
                {truncated ? (
                  <p className="text-sm text-muted-foreground">
                    Native error output was truncated. At most 8 lines of 512 characters each are
                    shown.
                  </p>
                ) : null}
              </section>
            ) : (
              <p className="text-sm text-muted-foreground">
                Native failure diagnostic not reported; native update outcome is not established by
                its absence.
              </p>
            )}
          </>
        )}
        <dl>
          <Fact label="Server report receipt">
            <ObservedTime value={receivedAt} server />
          </Fact>
        </dl>
      </CardContent>
    </Card>
  );
}
