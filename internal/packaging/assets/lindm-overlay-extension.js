// Lindm remote-assistance overlay. The per-user session helper draws the
// operator's pointer and bounded marks through this extension during a
// consented session. The surface is non-reactive (it is never picked, so all
// pointer and keyboard input reaches the desktop), draws only lines and a fixed
// pointer ring (never caller-supplied text or images), clamps to the shared
// monitor rectangle and sits below system modal dialogs and the lock screen.
//
// Only one session-bus client may draw: the first caller of Claim whose bus
// credentials show the same Unix user as the shell and whose process is the
// packaged session helper binary. Draw and Clear from any other sender are
// refused, and the claim ends when the helper's connection goes away.
import Gio from "gi://Gio";
import GLib from "gi://GLib";
import St from "gi://St";
import * as Main from "resource:///org/gnome/shell/ui/main.js";
import { Extension } from "resource:///org/gnome/shell/extensions/extension.js";

const BUS_NAME = "dev.lindm.AssistOverlay";
const OBJECT_PATH = "/dev/lindm/AssistOverlay";
const HELPER = "/usr/libexec/lindm/lindm-agent";
const ACCESS_DENIED = "org.freedesktop.DBus.Error.AccessDenied";
const MAX_STROKES = 16;
const MAX_POINTS = 64;
const MAX_EXTENT = 16384;
const IFACE = `<node>
  <interface name="dev.lindm.AssistOverlay1">
    <method name="Draw">
      <arg type="(iiii)" name="monitor" direction="in"/>
      <arg type="b" name="has_pointer" direction="in"/>
      <arg type="(dd)" name="pointer" direction="in"/>
      <arg type="aa(dd)" name="strokes" direction="in"/>
    </method>
    <method name="Clear"/>
    <method name="Claim"/>
    <property name="Version" type="u" access="read"/>
  </interface>
</node>`;

function unit(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1)
    throw new Error("coordinate out of range");
  return value;
}

export default class LindmOverlay extends Extension {
  enable() {
    this._frame = null;
    this._area = new St.DrawingArea({
      reactive: false,
      can_focus: false,
      track_hover: false,
      visible: false,
    });
    this._client = null;
    this._watch = 0;
    this._uid = new Gio.Credentials().get_unix_user();
    this._area.connect("repaint", (area) => this._repaint(area));
    Main.layoutManager.uiGroup.insert_child_below(this._area, Main.layoutManager.modalDialogGroup);
    this._exported = Gio.DBusExportedObject.wrapJSObject(IFACE, this);
    this._exported.export(Gio.DBus.session, OBJECT_PATH);
    this._owner = Gio.bus_own_name_on_connection(
      Gio.DBus.session,
      BUS_NAME,
      Gio.BusNameOwnerFlags.NONE,
      null,
      null,
    );
  }

  disable() {
    this._release();
    Gio.bus_unown_name(this._owner);
    this._exported.unexport();
    this._exported = null;
    this._area.destroy();
    this._area = null;
    this._frame = null;
  }

  get Version() {
    return 2;
  }

  // Binds drawing to the calling connection after verifying its credentials
  // with the bus daemon; the caller cannot assert its own identity.
  ClaimAsync(_params, invocation) {
    const sender = invocation.get_sender();
    if (this._client !== null) {
      if (this._client === sender) invocation.return_value(null);
      else invocation.return_dbus_error(ACCESS_DENIED, "overlay already claimed");
      return;
    }
    const connection = invocation.get_connection();
    connection.call(
      "org.freedesktop.DBus",
      "/org/freedesktop/DBus",
      "org.freedesktop.DBus",
      "GetConnectionCredentials",
      new GLib.Variant("(s)", [sender]),
      new GLib.VariantType("(a{sv})"),
      Gio.DBusCallFlags.NONE,
      -1,
      null,
      (bus, result) => {
        let trusted = false;
        try {
          const [credentials] = bus.call_finish(result).recursiveUnpack();
          trusted =
            this._exported !== null &&
            this._client === null &&
            credentials.UnixUserID === this._uid &&
            Number.isInteger(credentials.ProcessID) &&
            credentials.ProcessID > 0 &&
            [HELPER, `${HELPER} (deleted)`].includes(
              GLib.file_read_link(`/proc/${credentials.ProcessID}/exe`),
            );
        } catch {
          trusted = false;
        }
        if (!trusted) {
          invocation.return_dbus_error(ACCESS_DENIED, "overlay caller is not the session helper");
          return;
        }
        this._client = sender;
        this._watch = Gio.bus_watch_name_on_connection(
          connection,
          sender,
          Gio.BusNameWatcherFlags.NONE,
          null,
          () => this._release(),
        );
        invocation.return_value(null);
      },
    );
  }

  DrawAsync(params, invocation) {
    if (!this._authorized(invocation)) return;
    try {
      this._draw(...params);
    } catch (error) {
      invocation.return_dbus_error("org.freedesktop.DBus.Error.InvalidArgs", String(error.message));
      return;
    }
    invocation.return_value(null);
  }

  ClearAsync(_params, invocation) {
    if (!this._authorized(invocation)) return;
    this._clear();
    invocation.return_value(null);
  }

  _authorized(invocation) {
    if (this._client !== null && invocation.get_sender() === this._client) return true;
    invocation.return_dbus_error(
      ACCESS_DENIED,
      "overlay caller is not the claiming session helper",
    );
    return false;
  }

  _release() {
    if (this._watch) Gio.bus_unwatch_name(this._watch);
    this._watch = 0;
    this._client = null;
    if (this._area) this._clear();
  }

  _draw(monitor, hasPointer, pointer, strokes) {
    const [x, y, width, height] = monitor;
    if (
      !(width > 0 && height > 0 && width <= MAX_EXTENT && height <= MAX_EXTENT) ||
      strokes.length > MAX_STROKES
    )
      throw new Error("overlay frame out of bounds");
    const frame = { pointer: null, strokes: [] };
    if (hasPointer) frame.pointer = [unit(pointer[0]), unit(pointer[1])];
    for (const stroke of strokes) {
      if (stroke.length < 2 || stroke.length > MAX_POINTS)
        throw new Error("overlay stroke out of bounds");
      frame.strokes.push(stroke.map(([px, py]) => [unit(px), unit(py)]));
    }
    this._frame = frame;
    this._area.set_position(x, y);
    this._area.set_size(width, height);
    this._area.show();
    this._area.queue_repaint();
  }

  _clear() {
    this._frame = null;
    this._area.hide();
  }

  _repaint(area) {
    const cr = area.get_context();
    const [width, height] = area.get_surface_size();
    const frame = this._frame;
    if (frame) {
      cr.setLineWidth(4);
      cr.setSourceRGBA(0.93, 0.26, 0.21, 0.9);
      for (const stroke of frame.strokes) {
        cr.moveTo(stroke[0][0] * width, stroke[0][1] * height);
        for (const [px, py] of stroke.slice(1)) cr.lineTo(px * width, py * height);
        cr.stroke();
      }
      if (frame.pointer) {
        const [px, py] = frame.pointer;
        cr.setSourceRGBA(1.0, 0.6, 0.0, 0.95);
        cr.setLineWidth(5);
        cr.arc(px * width, py * height, 16, 0, 2 * Math.PI);
        cr.stroke();
        cr.arc(px * width, py * height, 4, 0, 2 * Math.PI);
        cr.fill();
      }
    }
    cr.$dispose();
  }
}
