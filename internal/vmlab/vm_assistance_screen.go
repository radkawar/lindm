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
// so luminance alone is not a portable signal.
func locateNotificationBanner(reference, current *image.RGBA) (image.Rectangle, bool) {
	display := current.Bounds()
	centre := display.Min.X + display.Dx()/2
	region := image.Rect(centre-420, display.Min.Y+gnomeTopBarHeight, centre+420, display.Min.Y+360)
	bounds, count := screenDiffBounds(reference, current, region, screenDiffThreshold)
	if count < 2000 || bounds.Dx() < 300 || bounds.Dx() > 760 || bounds.Dy() < 80 || bounds.Dy() > 320 {
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
	if dialog.Dx() < 450 || dialog.Dx() > 900 || dialog.Dy() < 300 || dialog.Dy() > 700 {
		return image.Rectangle{}, false
	}
	return dialog, true
}

// Header buttons and the RemoteDesktop "Allow Remote Interaction" switch sit
// at fixed offsets from the dialog edges on both GNOME 46 and GNOME 50.
func portalShareButton(dialog image.Rectangle) image.Point {
	return image.Pt(dialog.Max.X-44, dialog.Min.Y+22)
}

func portalCancelButton(dialog image.Rectangle) image.Point {
	return image.Pt(dialog.Min.X+46, dialog.Min.Y+22)
}

func portalControlSwitch(dialog image.Rectangle) image.Point {
	return image.Pt(dialog.Max.X-78, dialog.Min.Y+105)
}

// portalSwitchOn reports whether the switch track shows the theme accent
// (orange on Yaru, blue on Adwaita); an off switch is neutral grey and white.
func portalSwitchOn(img *image.RGBA, dialog image.Rectangle) bool {
	centre := portalControlSwitch(dialog)
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

// portalHasControlSwitch reports whether the dialog is the RemoteDesktop one a
// Control request opens: its "Allow Remote Interaction" switch track (grey off,
// accent on) covers the switch area. In the ScreenCast dialog of a view-only
// request that area is plain dialog background.
func portalHasControlSwitch(img *image.RGBA, dialog image.Rectangle) bool {
	centre := portalControlSwitch(dialog)
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

// centreChanged reports whether a window now covers the display centre, by
// comparing a central square with the clean reference.
func centreChanged(reference, current *image.RGBA) bool {
	display := current.Bounds()
	centre := image.Pt(display.Min.X+display.Dx()/2, display.Min.Y+display.Dy()/2)
	_, count := screenDiffBounds(reference, current, image.Rect(centre.X-120, centre.Y-120, centre.X+120, centre.Y+120), screenDiffThreshold)
	return count >= 240*240/2
}
