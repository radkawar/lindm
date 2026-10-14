// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

const fileChooserIface = "org.freedesktop.portal.FileChooser"

// ChooseFile asks the local user to select one file and returns its read-only
// descriptor. The caller must pause, release and drain remote input and clipboard
// injection before this call, and keep them paused until it returns. The caller
// owns the returned descriptor; neither the title nor any operator-supplied path
// selects a file. Context cancellation and the chooser's Cancel match
// ErrPortalCancelled; closing the chooser (Escape, response 2) returns
// ErrPortalClosed. Both end the request without a file and resume input.
// Context cancellation must end assistance rather than resume remote injection:
// Request.Close can fail, and even its acknowledgement is not local approval.
//
// OpenFile returns a URI, not an inode-bound capability (xdg-desktop-portal
// 1.18.4/1.21.1, src/file-chooser.c). The storage boundary immediately opens that
// URI without following symlinks and retains the descriptor; it cannot prove that
// the inode was unchanged between local selection and that open.
func (p *DesktopPortal) ChooseFile(ctx context.Context, title string) (selected *os.File, err error) {
	defer func() {
		if ctx.Err() == nil {
			return
		}
		err = errors.Join(ErrPortalCancelled, ctx.Err(), err)
		if selected != nil {
			if closeErr := selected.Close(); closeErr != nil {
				// os.File errors include its name; never propagate the selected path.
				var pathErr *os.PathError
				if errors.As(closeErr, &pathErr) {
					closeErr = pathErr.Err
				}
				err = errors.Join(err, fmt.Errorf("close chosen transfer file: %w", closeErr))
			}
			selected = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// As in Open, this well-known-name property read activates the portal before
	// resolving its unique owner. Directory selection is explicit since version 3.
	value, err := p.bus.property(ctx, portalName, portalPath, fileChooserIface, "version")
	if err != nil {
		return nil, unavailable("portal_file_chooser_unavailable", err)
	}
	version, ok := value.Value().(uint32)
	if !ok {
		return nil, unavailable("portal_file_chooser_version_invalid", nil)
	}
	if version < 3 {
		return nil, unavailable("portal_file_chooser_unsupported", nil)
	}
	owner, err := p.bus.nameOwner(ctx, portalName)
	if err != nil {
		return nil, unavailable("portal_unavailable", err)
	}
	names := p.bus.conn.Names()
	if len(names) == 0 {
		return nil, unavailable("session_bus_name_missing", nil)
	}
	sender := strings.ReplaceAll(strings.TrimPrefix(names[0], ":"), ".", "_")
	results, err := p.request(ctx, owner, sender, fileChooserIface+".OpenFile", []any{"", title}, map[string]dbus.Variant{
		"modal":     dbus.MakeVariant(true),
		"multiple":  dbus.MakeVariant(false),
		"directory": dbus.MakeVariant(false),
	})
	if errors.Is(err, errPortalOther) {
		// GNOME 46 answers Escape or the window's close with response 2; it
		// carries no URI, so it is the local user's refusal, not a failure
		// that ends assistance (layers-ubuntu24-files-17/-19).
		return nil, ErrPortalClosed
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	uri, err := chosenTransferURI(results)
	if err != nil {
		return nil, unavailable("portal_file_chooser_response_invalid", err)
	}
	return openChosenTransferFile(uri)
}

func chosenTransferURI(results map[string]dbus.Variant) (string, error) {
	value, ok := results["uris"]
	if !ok || value.Signature().String() != "as" {
		return "", errors.New("file chooser uris missing or invalid")
	}
	uris, ok := value.Value().([]string)
	if !ok || len(uris) != 1 || uris[0] == "" {
		return "", errors.New("file chooser must select exactly one URI")
	}
	// URI locality, bounded decoding and no-follow filesystem traversal belong
	// to openChosenTransferFile, not to a second chooser-specific path policy.
	return uris[0], nil
}
