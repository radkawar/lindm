// SPDX-License-Identifier: Apache-2.0

// Regression (ASSIST-T3-OVERLAY-DBUS): the packaged GNOME Shell overlay must
// refuse Draw and Clear from any session-bus sender except the one session
// helper connection whose bus-daemon credentials it verified in Claim. GNOME
// Shell modules are replaced by minimal stubs; the extension code is the
// packaged asset itself.
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";

const HELPER = "/usr/libexec/lindm/lindm-agent";
const UID = 1000;
const stubs = {
  "gi://Gio": "export default globalThis.__overlayStubs.Gio;",
  "gi://GLib": "export default globalThis.__overlayStubs.GLib;",
  "gi://St": "export default globalThis.__overlayStubs.St;",
  "resource:///org/gnome/shell/ui/main.js":
    "export const layoutManager = globalThis.__overlayStubs.layoutManager;",
  "resource:///org/gnome/shell/extensions/extension.js": "export class Extension {}",
};
registerHooks({
  resolve(specifier, context, next) {
    if (Object.hasOwn(stubs, specifier))
      return { url: `stub:${specifier}`, shortCircuit: true, format: "module" };
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.startsWith("stub:"))
      return { source: stubs[url.slice(5)], format: "module", shortCircuit: true };
    return next(url, context);
  },
});

// Bus-daemon view of each connection: credentials and process executable.
const peers = new Map();
const watchers = new Map();
const connection = {
  call(...args) {
    const [, , , method, parameters, , , , , callback] = args;
    assert.equal(method, "GetConnectionCredentials");
    const sender = parameters.value[0];
    callback(connection, sender);
  },
  call_finish(sender) {
    const peer = peers.get(sender);
    if (!peer) throw new Error("NameHasNoOwner");
    return { recursiveUnpack: () => [{ UnixUserID: peer.uid, ProcessID: peer.pid }] };
  },
};
class Area {
  connect() {}
  show() {
    this.visible = true;
  }
  hide() {
    this.visible = false;
  }
  set_position() {}
  set_size() {}
  queue_repaint() {}
  destroy() {}
}
globalThis.__overlayStubs = {
  Gio: {
    Credentials: class {
      get_unix_user() {
        return UID;
      }
    },
    DBusExportedObject: { wrapJSObject: () => ({ export() {}, unexport() {} }) },
    DBus: { session: connection },
    DBusCallFlags: { NONE: 0 },
    BusNameOwnerFlags: { NONE: 0 },
    BusNameWatcherFlags: { NONE: 0 },
    bus_own_name_on_connection: () => 1,
    bus_unown_name() {},
    bus_watch_name_on_connection(_connection, name, _flags, _appeared, vanished) {
      watchers.set(name, vanished);
      return watchers.size;
    },
    bus_unwatch_name() {},
  },
  GLib: {
    Variant: class {
      constructor(type, value) {
        this.type = type;
        this.value = value;
      }
    },
    VariantType: class {},
    file_read_link(path) {
      const pid = Number(/^\/proc\/(\d+)\/exe$/.exec(path)?.[1]);
      const peer = [...peers.values()].find((candidate) => candidate.pid === pid);
      if (!peer) throw new Error("ENOENT");
      return peer.exe;
    },
  },
  St: { DrawingArea: Area },
  layoutManager: { uiGroup: { insert_child_below() {} }, modalDialogGroup: {} },
};

const { default: LindmOverlay } =
  await import("../../internal/packaging/assets/lindm-overlay-extension.js");

function invoke(overlay, method, sender, params = []) {
  const invocation = {
    get_sender: () => sender,
    get_connection: () => connection,
    return_value() {
      this.ok = true;
    },
    return_dbus_error(name) {
      this.error = name;
    },
  };
  overlay[`${method}Async`](params, invocation);
  return invocation;
}

const frame = [[0, 0, 1920, 1080], true, [0.5, 0.5], []];
const denied = "org.freedesktop.DBus.Error.AccessDenied";

function enabled() {
  peers.clear();
  watchers.clear();
  peers.set(":1.5", { uid: UID, pid: 42, exe: HELPER });
  peers.set(":1.9", { uid: UID, pid: 77, exe: "/usr/bin/python3" });
  peers.set(":1.11", { uid: 1001, pid: 88, exe: HELPER });
  const overlay = new LindmOverlay();
  overlay.enable();
  return overlay;
}

test("unclaimed overlay refuses every draw", () => {
  const overlay = enabled();
  assert.equal(invoke(overlay, "Draw", ":1.5", frame).error, denied);
  assert.equal(invoke(overlay, "Clear", ":1.9").error, denied);
});

test("only the verified session helper claims and draws", () => {
  const overlay = enabled();
  assert.equal(invoke(overlay, "Claim", ":1.9").error, denied, "other binary of the same user");
  assert.equal(invoke(overlay, "Claim", ":1.11").error, denied, "helper binary of another user");
  assert.equal(invoke(overlay, "Claim", ":1.404").error, denied, "vanished sender");
  assert.equal(invoke(overlay, "Claim", ":1.5").ok, true);
  assert.equal(invoke(overlay, "Claim", ":1.5").ok, true, "claim is idempotent for its holder");
  assert.equal(invoke(overlay, "Draw", ":1.5", frame).ok, true);
  assert.equal(overlay._area.visible, true);
  assert.equal(invoke(overlay, "Draw", ":1.9", frame).error, denied);
  assert.equal(invoke(overlay, "Clear", ":1.9").error, denied);
  assert.equal(overlay._area.visible, true, "a foreign Clear had no effect");
  assert.equal(invoke(overlay, "Claim", ":1.9").error, denied, "claim cannot be taken over");
});

test("the claim ends with the helper connection", () => {
  const overlay = enabled();
  assert.equal(invoke(overlay, "Claim", ":1.5").ok, true);
  assert.equal(invoke(overlay, "Draw", ":1.5", frame).ok, true);
  watchers.get(":1.5")();
  assert.equal(overlay._area.visible, false, "vanished helper's marks are cleared");
  assert.equal(invoke(overlay, "Draw", ":1.5", frame).error, denied);
  peers.set(":1.6", { uid: UID, pid: 43, exe: `${HELPER} (deleted)` });
  assert.equal(invoke(overlay, "Claim", ":1.6").ok, true, "restarted helper after an upgrade");
});

test("invalid frames are refused for the claimed helper", () => {
  const overlay = enabled();
  invoke(overlay, "Claim", ":1.5");
  const invalid = invoke(overlay, "Draw", ":1.5", [[0, 0, 1920, 1080], true, [1.5, 0.5], []]);
  assert.equal(invalid.error, "org.freedesktop.DBus.Error.InvalidArgs");
});
