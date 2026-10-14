// SPDX-License-Identifier: Apache-2.0

import { build } from "vite";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Fault injection belongs solely to the operator's selected File reads. The
// production sender, channel.send, Ready/Cancel responses and RPCs are unchanged.
// The final hashing read is gated before Start so native held-key observation
// occurs after the UI releases control. Subsequent real source reads are paced
// one chunk at a time; all returned bytes come from the original Blob method.
export function createFileIsolationCommands(context) {
  const driver = {
    get page() {
      return context.driver.page;
    },
  };
  let bundle;
  async function installWire() {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const entry = resolve(root, "__lindm-isolation-wire.ts");
    // Use the console's pinned bundler, not an undeclared optional dependency.
    bundle ??= build({
      root,
      configFile: false,
      envDir: false,
      logLevel: "silent",
      plugins: [
        {
          name: "lindm-assistance-isolation-wire",
          resolveId(id) {
            if (id === entry) return entry;
          },
          load(id) {
            if (id === entry)
              return `export {create} from '@bufbuild/protobuf';
export {AssistanceFilePolicySchema} from './gen/lindm/agent/v1/assistance_files_pb.ts';
export {prepareFile, decodeFileFrame} from './src/features/assistance/files-stream.ts';`;
          },
        },
      ],
      build: {
        write: false,
        emptyOutDir: false,
        minify: false,
        lib: {
          entry,
          formats: ["iife"],
          name: "__lindmIsolationWire",
          fileName: "assistance-isolation",
        },
      },
    });
    const compiled = await bundle;
    const outputs = Array.isArray(compiled) ? compiled : [compiled];
    const chunks = outputs
      .flatMap((output) => output.output)
      .filter((item) => item.type === "chunk");
    if (chunks.length !== 1) throw new Error("assistance_file_wire_bundle_failed");
    await driver.page.evaluate(chunks[0].code);
  }
  async function cleanup() {
    await driver.page.evaluate(() => {
      const t = window.__lindmIsolationTransfer;
      if (!t) return;
      t.gate?.reject(new Error("isolation_source_gate_cancelled"));
      delete t.file.slice;
      t.channel.removeEventListener("message", t.listener);
      t.channel.removeEventListener("close", t.closed);
      t.channel.removeEventListener("error", t.closed);
      delete window.__lindmIsolationTransfer;
    });
  }
  async function rpc(method, payload) {
    const { url, csrf } = context.commandAuthority();
    if (!url || !csrf) throw new Error("isolation_command_authority_missing");
    return driver.page.evaluate(
      async ({ url, csrf, method, payload }) => {
        const sessionId = /\/assistance\/([0-9a-f-]{36})$/.exec(location.pathname)?.[1];
        if (!sessionId) throw new Error("isolation_session_missing");
        const response = await fetch(url.replace(/\/RunAssistanceCommand$/, `/${method}`), {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "X-CSRF-Token": csrf,
          },
          body: JSON.stringify({ sessionId, ...payload }),
        });
        const body = await response.json();
        return {
          ok: response.ok,
          httpStatus: response.status,
          code: body.code ?? "",
          reason: response.headers.get("Lindm-Reason") ?? "",
          body,
        };
      },
      { url, csrf, method, payload },
    );
  }
  async function report(requestId) {
    const result = await rpc("GetAssistanceFileTransfer", { requestId });
    if (!result.ok || result.body.transfer?.requestId !== requestId)
      throw new Error("isolation_file_rpc_failed");
    return result.body.transfer;
  }
  const commands = {
    async fileIsolationPrepare(args) {
      if (
        !context.evidenceDirectory ||
        dirname(resolve(args.file ?? "")) !== resolve(context.evidenceDirectory) ||
        !/^lindm-file-[a-f0-9]{24}\.txt$/.test(basename(args.file ?? ""))
      )
        throw new Error("isolation_fixture_required");
      await installWire();
      await driver.page.getByLabel("File to send", { exact: true }).setInputFiles(args.file);
      const prepared = await driver.page.evaluate(async () => {
        const wire = window.__lindmIsolationWire;
        const file = document.querySelector('input[type="file"]')?.files?.[0];
        if (!file || file.size !== 16777216) throw new Error("isolation_maximal_file_required");
        if (window.__lindmIsolationTransfer) throw new Error("isolation_transfer_already_present");
        const metadata = await wire.prepareFile(
          file,
          wire.create(wire.AssistanceFilePolicySchema, {
            maxFileBytes: 16777216n,
            maxSessionBytes: 67108864n,
            allowedMimeTypes: ["text/plain"],
            allowedExtensions: [".txt"],
          }),
          AbortSignal.timeout(30000),
          () => {},
        );
        const channel = window.__lindmLabPeers
          ?.at(-1)
          ?.inputs.find((value) => value.label === "lindm-files");
        if (
          !channel ||
          channel.readyState !== "open" ||
          !channel.ordered ||
          channel.maxRetransmits !== null ||
          channel.maxPacketLifeTime !== null
        )
          throw new Error("isolation_reliable_file_channel_required");
        const t = {
          file,
          channel,
          requestId: "",
          sent: 0,
          ready: "",
          cancel: "",
          error: "",
          wake: null,
          phase: "hashing",
          gate: null,
        };
        t.wait = async (condition) => {
          const signal = AbortSignal.timeout(30000);
          await new Promise((resolve, reject) => {
            const check = () => {
              if (t.error || signal.aborted) {
                clean();
                reject(new Error(t.error || "isolation_observation_timeout"));
              } else if (condition()) {
                clean();
                resolve();
              }
            };
            const clean = () => {
              t.wake = null;
              signal.removeEventListener("abort", check);
            };
            t.wake = check;
            signal.addEventListener("abort", check, { once: true });
            check();
          });
        };
        const nativeSlice = file.slice.bind(file);
        Object.defineProperty(file, "slice", {
          configurable: true,
          value(start, end, type) {
            const blob = nativeSlice(start, end, type);
            const hashGate =
              t.phase === "hashing" && start === file.size - 16384 && end === file.size;
            if (!hashGate && t.phase !== "streaming") return blob;
            if (end - start !== 16384 || (t.phase === "streaming" && start !== t.sent))
              throw new Error("isolation_unexpected_source_read");
            const nativeRead = blob.arrayBuffer.bind(blob);
            Object.defineProperty(blob, "arrayBuffer", {
              value: async () => {
                if (t.gate) throw new Error("isolation_concurrent_source_reads");
                const signal = AbortSignal.timeout(300000);
                await new Promise((resolve, reject) => {
                  const aborted = () => reject(new Error("isolation_source_deadline"));
                  t.gate = {
                    offset: start,
                    hash: hashGate,
                    resolve: () => {
                      signal.removeEventListener("abort", aborted);
                      t.gate = null;
                      resolve();
                    },
                    reject: (error) => {
                      signal.removeEventListener("abort", aborted);
                      t.gate = null;
                      reject(error);
                    },
                  };
                  signal.addEventListener("abort", aborted, { once: true });
                  t.wake?.();
                });
                const bytes = await nativeRead();
                if (hashGate) t.phase = "streaming";
                return bytes;
              },
            });
            return blob;
          },
        });
        t.listener = (event) => {
          try {
            const frame = wire.decodeFileFrame(event.data);
            if (frame.requestId !== t.requestId)
              throw new Error("isolation_foreign_receiver_frame");
            const bytes = btoa(String.fromCharCode(...new Uint8Array(event.data)));
            if (frame.body.case === "ready" && !t.ready) t.ready = bytes;
            else if (frame.body.case === "cancel" && !t.cancel) t.cancel = bytes;
            else throw new Error("isolation_unexpected_receiver_frame");
          } catch (error) {
            t.error = error.message;
          }
          t.wake?.();
        };
        t.closed = () => {
          t.error = "isolation_channel_closed";
          t.wake?.();
        };
        channel.addEventListener("message", t.listener);
        channel.addEventListener("close", t.closed);
        channel.addEventListener("error", t.closed);
        window.__lindmIsolationTransfer = t;
        return {
          name: file.name,
          bytes: file.size,
          sha256: Array.from(metadata.sha256, (b) => b.toString(16).padStart(2, "0")).join(""),
        };
      });
      await context.ui.click({ role: "button", text: "Send file" });
      await driver.page.evaluate(async () => {
        const t = window.__lindmIsolationTransfer;
        await t.wait(() => t.gate?.hash === true);
      });
      return prepared;
    },
    async fileIsolationStart() {
      const [response] = await Promise.all([
        driver.page.waitForResponse(
          (response) => /\/StartAssistanceFileTransfer$/.test(new URL(response.url()).pathname),
          { timeout: 30000 },
        ),
        driver.page.evaluate(() => {
          const t = window.__lindmIsolationTransfer;
          if (!t?.gate?.hash || t.error) throw new Error("isolation_metadata_gate_missing");
          t.gate.resolve();
        }),
      ]);
      const body = await response.json();
      if (!response.ok() || !body.transfer?.requestId)
        throw new Error("isolation_actual_ui_start_failed");
      await driver.page.evaluate((requestId) => {
        window.__lindmIsolationTransfer.requestId = requestId;
      }, body.transfer.requestId);
      return body.transfer;
    },
    async fileIsolationState(args) {
      return report(args.requestId);
    },
    async fileIsolationStep(args) {
      const current = await report(args.requestId);
      if (current.state !== "ASSISTANCE_FILE_STATE_TRANSFERRING")
        throw new Error("isolation_stream_not_authorized");
      return driver.page.evaluate(async (requestId) => {
        const t = window.__lindmIsolationTransfer;
        if (!t || t.requestId !== requestId || t.error || t.sent >= 32768)
          throw new Error("isolation_invalid_stream_step");
        await t.wait(() => t.ready && t.gate && !t.gate.hash && t.gate.offset === t.sent);
        const offset = t.sent;
        // The production loop awaits each real send before requesting its next
        // source slice. Seeing that next read, then SSH-reading receiver bytes,
        // establishes progress; bufferedAmount alone is never a delivery claim.
        t.sent += 16384;
        t.gate.resolve();
        await t.wait(() => t.gate && !t.gate.hash && t.gate.offset === offset + 16384);
        return {
          request_id: requestId,
          channel: t.channel.label,
          ordered: t.channel.ordered,
          bytes_sent: t.sent,
          ready_frame: t.ready,
          buffered_amount: t.channel.bufferedAmount,
        };
      }, args.requestId);
    },
    async fileIsolationCancel(args) {
      await driver.page.evaluate((requestId) => {
        const t = window.__lindmIsolationTransfer;
        if (!t || t.requestId !== requestId || t.sent !== 32768 || !t.gate || t.error)
          throw new Error("isolation_cancel_not_partial");
      }, args.requestId);
      const [response] = await Promise.all([
        driver.page.waitForResponse(
          (response) => /\/CancelAssistanceFileTransfer$/.test(new URL(response.url()).pathname),
          { timeout: 30000 },
        ),
        context.ui.click({ role: "button", text: "Cancel transfer" }),
      ]);
      const body = await response.json();
      if (!response.ok() || body.transfer?.requestId !== args.requestId)
        throw new Error("isolation_actual_ui_cancel_failed");
      const cancel = await driver.page.evaluate(async () => {
        const t = window.__lindmIsolationTransfer;
        await t.wait(() => Boolean(t.cancel));
        return t.cancel;
      });
      await cleanup();
      return { report: body.transfer, cancel_frame: cancel };
    },
    async fileIsolationInput(args) {
      if (!Array.isArray(args.frames) || !args.frames.length || args.frames.length > 24)
        throw new Error("isolation_input_bound");
      return driver.page.evaluate((frames) => {
        const channel = window.__lindmLabPeers
          ?.at(-1)
          ?.inputs.find((value) => value.label === "lindm-input");
        if (
          !channel ||
          channel.readyState !== "open" ||
          !channel.ordered ||
          channel.maxRetransmits !== null ||
          channel.maxPacketLifeTime !== null
        )
          throw new Error("isolation_reliable_input_channel_required");
        for (const raw of frames) {
          if (typeof raw !== "string" || new TextEncoder().encode(raw).length > 256)
            throw new Error("isolation_input_frame_bound");
          const frame = JSON.parse(raw);
          if (
            !["key", "move", "button"].includes(frame.t) ||
            !Number.isInteger(frame.epoch) ||
            frame.epoch <= 0
          )
            throw new Error("isolation_input_frame_invalid");
          channel.send(raw);
        }
        return {
          channel: channel.label,
          ordered: channel.ordered,
          frames,
          buffered_amount: channel.bufferedAmount,
        };
      }, args.frames);
    },
    async fileModalRefuse(args) {
      if (
        !["clipboard_write", "clipboard_read", "special_keys"].includes(args.kind) ||
        !/^[a-f0-9]{24}$/.test(args.text ?? "")
      )
        throw new Error("isolation_command_probe_invalid");
      const actor = await context.identity();
      const requestId = await driver.page.evaluate(() => crypto.randomUUID());
      const command = { requestId, kind: `ASSISTANCE_COMMAND_KIND_${args.kind.toUpperCase()}` };
      if (args.kind === "clipboard_write") command.text = args.text;
      if (args.kind === "special_keys") command.specialKey = "ASSISTANCE_SPECIAL_KEY_CLOSE_WINDOW";
      const result = await rpc("RunAssistanceCommand", { command });
      if (
        result.ok ||
        result.code !== "failed_precondition" ||
        result.reason !== "assistance_input_paused"
      )
        throw new Error("isolation_modal_refusal_missing");
      return {
        request_id: requestId,
        kind: args.kind,
        actor,
        code: result.code,
        reason: result.reason,
        http_status: result.httpStatus,
      };
    },
    async fileIsolationCleanup() {
      await cleanup();
      return {};
    },
  };
  // Failures restore the selected File and reject outstanding real reads. They
  // never synthesize success, swallow a failed probe or suppress product events.
  return Object.fromEntries(
    Object.entries(commands).map(([name, command]) => [
      name,
      async (...args) => {
        try {
          return await command(...args);
        } catch (error) {
          try {
            await cleanup();
          } catch (cleanupError) {
            throw new AggregateError([error, cleanupError], "isolation_cleanup_failed");
          }
          throw error;
        }
      },
    ]),
  );
}
