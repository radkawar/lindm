// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"image"
	"slices"
)

// The desktop locators below read QMP screendumps of the lab's GNOME guests
// (Ubuntu 24.04 GNOME 46 and Fedora 44 GNOME 50, observed in Phase 1). They
// locate only the local user's consent surfaces; every click is followed by a
// server-state oracle, so a misplaced click fails the lane instead of passing.
const (
	// gnomeTopBarHeight excludes the clock and sharing indicator, which change
	// independently of notification banners.
	gnomeTopBarHeight = 34
	// screenDiffThreshold ignores compression-free rendering noise and banner
	// shadows; banners differ from wallpaper by far more on every channel.
	screenDiffThreshold = 48
	// Banner action rows are ~40 px tall and end ~10 px above the banner edge.
	bannerActionInset = 24
	lightLuma         = 200
)

func pixelLuma(img *image.RGBA, x, y int) int {
	offset := img.PixOffset(x, y)
	r, g, b := int(img.Pix[offset]), int(img.Pix[offset+1]), int(img.Pix[offset+2])
	return (299*r + 587*g + 114*b) / 1000
}

func pixelSaturation(img *image.RGBA, x, y int) int {
	offset := img.PixOffset(x, y)
	r, g, b := int(img.Pix[offset]), int(img.Pix[offset+1]), int(img.Pix[offset+2])
	return max(r, g, b) - min(r, g, b)
}

// screenDiffBounds returns the bounding box of pixels in region whose colour
// differs from reference on any channel by more than threshold, and how many
// such pixels exist. Both images must share dimensions.
func screenDiffBounds(reference, current *image.RGBA, region image.Rectangle, threshold int) (image.Rectangle, int) {
	if reference.Bounds() != current.Bounds() {
		return image.Rectangle{}, 0
	}
	region = region.Intersect(current.Bounds())
	var bounds image.Rectangle
	count := 0
	for y := region.Min.Y; y < region.Max.Y; y++ {
		for x := region.Min.X; x < region.Max.X; x++ {
			a, b := reference.PixOffset(x, y), current.PixOffset(x, y)
			differs := false
			for channel := range 3 {
				delta := int(reference.Pix[a+channel]) - int(current.Pix[b+channel])
				if delta > threshold || -delta > threshold {
					differs = true
					break
				}
			}
			if !differs {
				continue
			}
			count++
			pixel := image.Rect(x, y, x+1, y+1)
			if bounds.Empty() {
				bounds = pixel
			} else {
				bounds = bounds.Union(pixel)
			}
		}
	}
	return bounds, count
}

// pointerHoverSettled requires visible feedback at the intended control, not
// just QMP's acknowledgment that motion was queued. Two frames must agree after
// that feedback appears, so a click cannot race the compositor's hover update.
func pointerHoverSettled(before, previous, current *image.RGBA, point image.Point) bool {
	region := image.Rect(point.X-20, point.Y-20, point.X+20, point.Y+20)
	_, changed := screenDiffBounds(before, current, region, 3)
	_, moving := screenDiffBounds(previous, current, region, 3)
	return changed >= 16 && moving < 16
}

// locateNotificationBanner finds a GNOME notification banner in the top-centre
// banner area by comparing with a clean reference of the same desktop. GNOME
// draws light banners on Ubuntu's Yaru theme and dark ones on Fedora's Adwaita,
// so luminance alone is not a portable signal. A two-line banner without
// actions is about 76 px tall on GNOME 43 and 48 (no header row), so the floor
// sits below it: missing the "ended" notice let waitNoBanner pass while GNOME
// kept it on the idle seat and queued the next consent prompt behind it.
func locateNotificationBanner(reference, current *image.RGBA) (image.Rectangle, bool) {
	display := current.Bounds()
	centre := display.Min.X + display.Dx()/2
	region := image.Rect(centre-420, display.Min.Y+gnomeTopBarHeight, centre+420, display.Min.Y+360)
	bounds, count := screenDiffBounds(reference, current, region, screenDiffThreshold)
	if count < 2000 || bounds.Dx() < 300 || bounds.Dx() > 760 || bounds.Dy() < 64 || bounds.Dy() > 320 {
		return image.Rectangle{}, false
	}
	return bounds, true
}

// notificationActionPoint returns the centre of action index (0-based, in
// declaration order) on a banner showing actions buttons in one row.
func notificationActionPoint(banner image.Rectangle, actions, index int) image.Point {
	width := banner.Dx()
	return image.Pt(banner.Min.X+width*(2*index+1)/(2*actions), banner.Max.Y-bannerActionInset)
}

// locatePortalDialog finds the xdg-desktop-portal-gnome share dialog: the only
// large light rectangle on the controlled desktop. Rows whose longest light run
// agrees on both edges vote for the dialog bounds, so text and controls inside
// the dialog, and its rounded corners, do not move the result.
func locatePortalDialog(img *image.RGBA) (image.Rectangle, bool) {
	display := img.Bounds()
	type run struct{ y, start, end int }
	var runs []run
	for y := display.Min.Y + gnomeTopBarHeight; y < display.Max.Y; y++ {
		bestStart, bestEnd, start := 0, 0, -1
		for x := display.Min.X; x <= display.Max.X; x++ {
			light := x < display.Max.X && pixelLuma(img, x, y) >= lightLuma
			if light && start < 0 {
				start = x
			}
			if !light && start >= 0 {
				if x-start > bestEnd-bestStart {
					bestStart, bestEnd = start, x
				}
				start = -1
			}
		}
		if bestEnd-bestStart >= 450 {
			runs = append(runs, run{y, bestStart, bestEnd})
		}
	}
	if len(runs) < 100 {
		return image.Rectangle{}, false
	}
	// The most common exact edges are the dialog's straight sides.
	votes := map[[2]int]int{}
	for _, r := range runs {
		votes[[2]int{r.start, r.end}]++
	}
	var edges [2]int
	best := 0
	for key, count := range votes {
		if count > best || (count == best && (key[0] < edges[0] || (key[0] == edges[0] && key[1] < edges[1]))) {
			edges, best = key, count
		}
	}
	// Rounded corners shorten the first and last rows by at most the radius.
	const cornerTolerance = 16
	var rows []int
	for _, r := range runs {
		if r.start >= edges[0] && r.start-edges[0] <= cornerTolerance && r.end <= edges[1] && edges[1]-r.end <= cornerTolerance {
			rows = append(rows, r.y)
		}
	}
	dialog := image.Rect(edges[0], slices.Min(rows), edges[1], slices.Max(rows)+1)
	// GNOME 43's RemoteDesktop dialog is 500x300 and its ScreenCast dialog
	// lacks the switch row, so the floor admits a one-monitor list dialog.
	if dialog.Dx() < 450 || dialog.Dx() > 900 || dialog.Dy() < 200 || dialog.Dy() > 700 {
		return image.Rectangle{}, false
	}
	return dialog, true
}

// Header buttons sit at fixed offsets from the dialog edges on GNOME 43, 46,
// 48 and 50.
func portalShareButton(dialog image.Rectangle) image.Point {
	return image.Pt(dialog.Max.X-44, dialog.Min.Y+22)
}

func portalCancelButton(dialog image.Rectangle) image.Point {
	return image.Pt(dialog.Min.X+46, dialog.Min.Y+22)
}

// portalSwitchCandidates are where a RemoteDesktop dialog's "Allow Remote
// Interaction" switch sits: GNOME 46, 48 and 50 put it first, under the
// header; GNOME 42 and 43 put it in the dialog's last row, after the monitor
// list. The newer layout is tried first.
func portalSwitchCandidates(dialog image.Rectangle) [2]image.Point {
	return [2]image.Point{
		image.Pt(dialog.Max.X-78, dialog.Min.Y+105),
		image.Pt(dialog.Max.X-70, dialog.Max.Y-78),
	}
}

// portalControlSwitch locates the RemoteDesktop dialog a Control request
// opens: the candidate whose area the switch track (grey off, accent on)
// covers. In the ScreenCast dialog of a view-only request every candidate is
// plain dialog, list or monitor background.
func portalControlSwitch(img *image.RGBA, dialog image.Rectangle) (image.Point, bool) {
	for _, centre := range portalSwitchCandidates(dialog) {
		if portalSwitchTrack(img, dialog, centre) {
			return centre, true
		}
	}
	return image.Point{}, false
}

func portalSwitchTrack(img *image.RGBA, dialog image.Rectangle, centre image.Point) bool {
	area := image.Rect(centre.X-18, centre.Y-8, centre.X+18, centre.Y+8).Intersect(img.Bounds())
	if area.Empty() || !image.Pt(dialog.Min.X+16, centre.Y).In(img.Bounds()) {
		return false
	}
	background := pixelLuma(img, dialog.Min.X+16, centre.Y)
	marked := 0
	for y := area.Min.Y; y < area.Max.Y; y++ {
		for x := area.Min.X; x < area.Max.X; x++ {
			if luma := pixelLuma(img, x, y); luma <= background-16 || luma >= background+16 || pixelSaturation(img, x, y) >= 90 {
				marked++
			}
		}
	}
	return marked*10 >= area.Dx()*area.Dy()*3
}

// portalSwitchOn reports whether the switch track at centre shows the theme
// accent (orange on Yaru, blue on Adwaita); an off switch is neutral grey and
// white.
func portalSwitchOn(img *image.RGBA, centre image.Point) bool {
	area := image.Rect(centre.X-18, centre.Y-8, centre.X+18, centre.Y+8).Intersect(img.Bounds())
	if area.Empty() {
		return false
	}
	saturated := 0
	for y := area.Min.Y; y < area.Max.Y; y++ {
		for x := area.Min.X; x < area.Max.X; x++ {
			if pixelSaturation(img, x, y) >= 90 {
				saturated++
			}
		}
	}
	return saturated*10 >= area.Dx()*area.Dy()*3
}

// portalRow is one GNOME 41 list row the local user must select.
type portalRow struct {
	name   string
	centre image.Point
}

// gnome41PortalRows locates the selection rows of xdg-desktop-portal-gnome
// 41's share dialogs (GNOME 40, Enterprise Linux 9). They have no "Allow
// Remote Interaction" switch and preselect nothing: Share stays insensitive
// until the monitor row and, in the RemoteDesktop dialog, the keyboard and
// pointer rows are selected. The monitor list sits under the 47 px header and
// its heading; the device list ends 32 px above the dialog edge (observed in
// the Rocky Linux 9.8 500x402 RemoteDesktop dialog). Every row's frame lines
// must be present, so another layout is never clicked by position.
func gnome41PortalRows(img *image.RGBA, dialog image.Rectangle, control bool) ([]portalRow, bool) {
	centreX := dialog.Min.X + dialog.Dx()/2
	if !portalListFrame(img, dialog, dialog.Min.Y+122, dialog.Min.Y+170) {
		return nil, false
	}
	rows := []portalRow{{"monitor", image.Pt(centreX, dialog.Min.Y+146)}}
	if !control {
		return rows, true
	}
	if !portalListFrame(img, dialog, dialog.Max.Y-129, dialog.Max.Y-81, dialog.Max.Y-33) {
		return nil, false
	}
	return append(rows, portalRow{"keyboard", image.Pt(centreX, dialog.Max.Y-105)}, portalRow{"pointer", image.Pt(centreX, dialog.Max.Y-57)}), true
}

// portalListFrame reports whether a framed list spans the given border rows
// near both dialog edges, away from row labels: each border is a mid-grey
// line, and the dialog background shows just outside the first and last.
func portalListFrame(img *image.RGBA, dialog image.Rectangle, borders ...int) bool {
	for _, x := range []int{dialog.Min.X + 50, dialog.Max.X - 50} {
		outside := []image.Point{image.Pt(x, borders[0]-3), image.Pt(x, borders[len(borders)-1]+3)}
		for _, point := range outside {
			if !point.In(img.Bounds()) || pixelLuma(img, point.X, point.Y) < 235 {
				return false
			}
		}
		for _, y := range borders {
			if !image.Pt(x, y).In(img.Bounds()) {
				return false
			}
			if luma := pixelLuma(img, x, y); luma < 170 || luma > 225 {
				return false
			}
		}
	}
	return true
}

// portalRowSelected reports whether a GNOME 41 list row shows the selection
// accent beside its label; an unselected row is plain white.
func portalRowSelected(img *image.RGBA, dialog image.Rectangle, row image.Point) bool {
	return portalSwitchOn(img, image.Pt(dialog.Min.X+60, row.Y))
}

// portalShareSensitive reports whether the header's Share button can be
// pressed: an accent (suggested-action) button or label text as dark as
// Cancel's. GNOME 41 greys an insensitive Share label instead.
func portalShareSensitive(img *image.RGBA, dialog image.Rectangle) bool {
	darkest := func(area image.Rectangle) (int, int) {
		minimum, saturated := 255, 0
		area = area.Intersect(img.Bounds())
		for y := area.Min.Y; y < area.Max.Y; y++ {
			for x := area.Min.X; x < area.Max.X; x++ {
				minimum = min(minimum, pixelLuma(img, x, y))
				if pixelSaturation(img, x, y) >= 90 {
					saturated++
				}
			}
		}
		return minimum, saturated
	}
	share := portalShareButton(dialog)
	shareDarkest, shareAccent := darkest(image.Rect(share.X-26, share.Y-10, share.X+26, share.Y+10))
	cancel := portalCancelButton(dialog)
	cancelDarkest, _ := darkest(image.Rect(cancel.X-28, cancel.Y-10, cancel.X+28, cancel.Y+10))
	return shareAccent*10 >= 52*20 || shareDarkest <= cancelDarkest+40
}

// centreWindowThreshold is any change in a lossless screendump of a static
// wallpaper. A window replaces the pixels outright, but it can match the
// wallpaper closely: Rocky 9's dark gnome-terminal (29,29,27) over its navy
// wallpaper (8,19,29) moved only the wallpaper's grey stripes, 36% of the
// square, by more than screenDiffThreshold.
const centreWindowThreshold = 8

// centreChanged reports whether a window now covers the display centre, by
// comparing a central square with the clean reference.
func centreChanged(reference, current *image.RGBA) bool {
	display := current.Bounds()
	centre := image.Pt(display.Min.X+display.Dx()/2, display.Min.Y+display.Dy()/2)
	_, count := screenDiffBounds(reference, current, image.Rect(centre.X-120, centre.Y-120, centre.X+120, centre.Y+120), centreWindowThreshold)
	return count >= 240*240/2
}

// portalMonitorTiles locates the two unselected monitor illustration top
// borders, not a fabricated second monitor. GNOME 46/50 screencastwidget.css
// uses neutral shade(view_bg, .8) borders and accent borders when checked.
// Each border is a band of at least two neutral rows ≥70 px wide; its rounded
// corners widen it row by row, and the tiles are sized after each monitor's
// resolution, so two choices need not share extents or a top row (the
// primary head's tile also draws its top bar right below the border). A tile's
// bottom border overlaps its top horizontally and is skipped, as is the
// single-row frame around the choices. Both choices must lie side by side,
// below the interaction controls; the final Start response remains the
// authority for two consented streams.
func portalMonitorTiles(img *image.RGBA, dialog image.Rectangle) ([2]image.Rectangle, bool) {
	area := image.Rect(dialog.Min.X+40, dialog.Min.Y+160, dialog.Max.X-40, dialog.Max.Y-36).Intersect(img.Bounds())
	// A choice leaves room for a second ≥70 px choice and the 8 px gap.
	maxWidth := area.Dx() - 78
	var tiles []image.Rectangle
	accept := func(band image.Rectangle) {
		if band.Dy() < 2 || band.Dx() > maxWidth {
			return
		}
		for _, tile := range tiles {
			if band.Min.X < tile.Max.X+8 && tile.Min.X < band.Max.X+8 {
				return
			}
		}
		tiles = append(tiles, band)
	}
	var open []image.Rectangle
	for y := area.Min.Y; y <= area.Max.Y; y++ {
		var bands []image.Rectangle
		continued := make([]bool, len(open))
		start := -1
		for x := area.Min.X; y < area.Max.Y && x <= area.Max.X; x++ {
			neutral := x < area.Max.X && pixelLuma(img, x, y) >= 140 && pixelLuma(img, x, y) < 225 && pixelSaturation(img, x, y) < 40
			if neutral && start < 0 {
				start = x
			}
			if !neutral && start >= 0 {
				if x-start >= 70 {
					band := image.Rect(start, y, x, y+1)
					for i, previous := range open {
						if previous.Min.X < band.Max.X && band.Min.X < previous.Max.X {
							band, continued[i] = band.Union(previous), true
						}
					}
					bands = append(bands, band)
				}
				start = -1
			}
		}
		for i, band := range open {
			if !continued[i] {
				accept(band)
			}
		}
		open = bands
	}
	if len(tiles) != 2 {
		return [2]image.Rectangle{}, false
	}
	if tiles[1].Min.X < tiles[0].Min.X {
		tiles[0], tiles[1] = tiles[1], tiles[0]
	}
	return [2]image.Rectangle{tiles[0], tiles[1]}, true
}

func portalMonitorSelected(img *image.RGBA, border image.Rectangle) bool {
	area := border.Inset(-5).Intersect(img.Bounds())
	accent := 0
	for y := area.Min.Y; y < area.Max.Y; y++ {
		for x := area.Min.X; x < area.Max.X; x++ {
			if pixelSaturation(img, x, y) >= 90 {
				accent++
			}
		}
	}
	return accent >= border.Dx()
}
