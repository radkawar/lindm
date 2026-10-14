#!/usr/bin/python3
"""Disposable lab GTK client; observes real seat/clipboard events, never portals.

The production session helper remains the only portal client. This application
acts as the consenting user's paste target/copy source and per-monitor pointer
surface. All state is bounded and written only by actual GTK event callbacks.
"""
import json
import os
import secrets
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk  # noqa: E402

path, required = sys.argv[1], int(sys.argv[2])
display = Gdk.Display.get_default()
if display.get_n_monitors() != required:
    raise SystemExit("unexpected active guest monitor count")
if display.__gtype__.name != "GdkWaylandDisplay":
    raise SystemExit("native Wayland witness required")
bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
user_path = bus.call_sync(
    "org.freedesktop.login1", "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager", "GetUser",
    GLib.Variant("(u)", (os.getuid(),)), GLib.VariantType("(o)"),
    Gio.DBusCallFlags.NONE, 5000, None).unpack()[0]


def login_property(path, interface, name):
    return bus.call_sync(
        "org.freedesktop.login1", path, "org.freedesktop.DBus.Properties", "Get",
        GLib.Variant("(ss)", (interface, name)), GLib.VariantType("(v)"),
        Gio.DBusCallFlags.NONE, 5000, None).unpack()[0]


session_id, session_path = login_property(user_path, "org.freedesktop.login1.User", "Display")
session_type = login_property(session_path, "org.freedesktop.login1.Session", "Type")
if session_type != "wayland":
    raise SystemExit("native witness user has no Wayland display session")
state = {
    "backend": display.__gtype__.name,
    "display": display.get_name(),
    "uid": os.getuid(),
    "pid": os.getpid(),
    "session_id": session_id,
    "session_type": session_type,
    "monitors": [],
    "active_monitors": required,
    "removed_heads": [],
    "clipboard_source": secrets.token_hex(12),
    "pasted": "",
    "paste_serial": 0,
    "keys": [],
    "releases": [],
    "clicks": [],
    "closed": [],
    "layout_y": "",
    "layout_z": "",
}
windows = []
monitor_objects = []
clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)


def persist():
    with open(path + ".new", "w", encoding="utf-8") as stream:
        json.dump(state, stream)
    os.replace(path + ".new", path)

def layout_changed(keymap):
    state["layout_y"] = Gdk.keyval_name(keymap.translate_keyboard_state(29, 0, 0)[1])
    state["layout_z"] = Gdk.keyval_name(keymap.translate_keyboard_state(52, 0, 0)[1])
    persist()



def pasted(_clipboard, text, _data):
    state["pasted"] = (text or "")[:16384]
    state["paste_serial"] += 1
    persist()


def released(_window, event, _head):
    if len(state["releases"]) >= 32:
        Gtk.main_quit()
        return True
    state["releases"].append(Gdk.keyval_name(event.keyval))
    persist()
    return True


def key(_window, event, head):
    if len(state["keys"]) >= 32:
        Gtk.main_quit()
        return True
    state["keys"].append({"head": head, "symbol": Gdk.keyval_name(event.keyval),
                          "unicode": Gdk.keyval_to_unicode(event.keyval),
                          "layout_z": state["layout_z"]})
    if event.state & Gdk.ModifierType.CONTROL_MASK:
        if event.keyval in (Gdk.KEY_v, Gdk.KEY_V):
            clipboard.request_text(pasted, None)
        if event.keyval in (Gdk.KEY_c, Gdk.KEY_C):
            clipboard.set_text(state["clipboard_source"], -1)
    persist()
    return True


def click(area, event, head):
    # GTK 3 also delivers its synthesized 2BUTTON/3BUTTON_PRESS here after a
    # second press; only real presses are clicks.
    if event.type != Gdk.EventType.BUTTON_PRESS:
        return True
    if len(state["clicks"]) >= 32:
        Gtk.main_quit()
        return True
    state["clicks"].append({"head": head,
                            "x": event.x / area.get_allocated_width(),
                            "y": event.y / area.get_allocated_height()})
    area.grab_focus()
    persist()
    return True


def closed(_window, _event, head):
    state["closed"].append(head)
    persist()
    return False


def draw(area, cr, head):
    cr.set_source_rgb(*( (0.8, 0.05, 0.05) if head == 0 else (0.05, 0.05, 0.8) ))
    cr.paint()
    cr.set_source_rgb(1, 1, 1)
    cr.set_font_size(36)
    cr.move_to(60, 120)
    cr.show_text("LINDM REAL HEAD " + str(head))
    cr.set_font_size(24)
    cr.move_to(60, 170)
    cr.show_text("Copy source: " + state["clipboard_source"])
    # Browser decoder: assistance-marker.mjs. 0xa7, head, then the fresh
    # 12-byte nonce, MSB first in eight rows of fourteen complementary pairs.
    # This is painted on the actual fullscreen GTK surface, not a media echo.
    payload = bytes((0xa7, head)) + bytes.fromhex(state["clipboard_source"])
    width, height = area.get_allocated_width(), area.get_allocated_height()
    cell_width, cell_height = width * 0.8 / 28, height * 0.28 / 8
    for bit in range(112):
        value = (payload[bit // 8] >> (7 - bit % 8)) & 1
        for half in range(2):
            shade = value if half == 0 else 1 - value
            cr.set_source_rgb(shade, shade, shade)
            cr.rectangle(width * 0.1 + (bit % 14 * 2 + half) * cell_width,
                         height * 0.65 + (bit // 14) * cell_height,
                         cell_width, cell_height)
            cr.fill()
    return False


def monitor_removed(_display, removed):
    state["active_monitors"] = display.get_n_monitors()
    for head, monitor in enumerate(monitor_objects):
        if monitor == removed:
            state["removed_heads"].append(head)
            # Do not let Mutter relocate the removed-head marker onto the
            # surviving output and obscure a forbidden stream fallback.
            windows[head].hide()
    persist()


for head in range(required):
    monitor = display.get_monitor(head)
    monitor_objects.append(monitor)
    geometry = monitor.get_geometry()
    state["monitors"].append({"head": head, "model": monitor.get_model(),
                              "x": geometry.x, "y": geometry.y,
                              "width": geometry.width, "height": geometry.height})
    window = Gtk.Window(title="Lindm assistance fixture head " + str(head))
    area = Gtk.DrawingArea()
    area.set_can_focus(True)
    area.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
    area.connect("draw", draw, head)
    area.connect("button-press-event", click, head)
    window.connect("key-press-event", key, head)
    window.connect("key-release-event", released, head)
    window.connect("delete-event", closed, head)
    window.add(area)
    window.fullscreen_on_monitor(window.get_screen(), head)
    window.show_all()
    windows.append(window)
persist()
display.connect("monitor-removed", monitor_removed)
keymap = Gdk.Keymap.get_for_display(display)
keymap.connect("keys-changed", layout_changed)
layout_changed(keymap)
GLib.timeout_add_seconds(600, lambda: (Gtk.main_quit(), False)[1])
Gtk.main()
