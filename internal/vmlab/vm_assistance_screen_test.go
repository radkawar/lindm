package vmlab

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Synthetic desktops reproduce the geometry observed on the Phase-1 Ubuntu
// 24.04 (GNOME 46, light banners) and Fedora 44 (GNOME 50, dark banners)
// goldens at the lab's 1280x800 display.
func syntheticWallpaper(base color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 1280, 800))
	for y := range 800 {
		for x := range 1280 {
			img.SetRGBA(x, y, color.RGBA{base.R + uint8(x/80), base.G + uint8(y/80), base.B, 0xff})
		}
	}
	// Top bar with a clock that changes independently of banners.
	fill(img, image.Rect(0, 0, 1280, 32), color.RGBA{0, 0, 0, 0xff})
	return img
}

func fill(img *image.RGBA, r image.Rectangle, c color.RGBA) {
	draw.Draw(img, r, &image.Uniform{c}, image.Point{}, draw.Src)
}

func clone(img *image.RGBA) *image.RGBA {
	out := image.NewRGBA(img.Bounds())
	copy(out.Pix, img.Pix)
	return out
}

func TestPointerHoverRequiresRenderedStableFeedbackAtTarget(t *testing.T) {
	before := syntheticWallpaper(color.RGBA{60, 20, 50, 0xff})
	point := image.Pt(548, 204)
	if pointerHoverSettled(before, before, before, point) {
		t.Fatal("queued motion without rendered feedback allowed a click")
	}
	hover := clone(before)
	fill(hover, image.Rect(530, 190, 566, 220), color.RGBA{225, 225, 225, 0xff})
	if pointerHoverSettled(before, before, hover, point) {
		t.Fatal("the first changing frame was considered settled")
	}
	if !pointerHoverSettled(before, hover, hover, point) {
		t.Fatal("stable hover feedback was not recognized")
	}
	elsewhere := clone(before)
	fill(elsewhere, image.Rect(600, 8, 700, 24), color.RGBA{255, 255, 255, 0xff})
	if pointerHoverSettled(before, elsewhere, elsewhere, point) {
		t.Fatal("an unrelated clock tick allowed a click")
	}
}

func TestLocateNotificationBannerOnLightAndDarkThemes(t *testing.T) {
	for _, theme := range []struct {
		name               string
		wallpaper, banner  color.RGBA
		bounds             image.Rectangle
		allow, decline, op image.Point
	}{
		{"ubuntu", color.RGBA{60, 20, 50, 0xff}, color.RGBA{250, 250, 250, 0xff}, image.Rect(423, 36, 923, 192), image.Pt(548, 168), image.Pt(798, 168), image.Pt(673, 168)},
		{"fedora", color.RGBA{0, 60, 200, 0xff}, color.RGBA{58, 58, 62, 0xff}, image.Rect(383, 36, 896, 198), image.Pt(511, 174), image.Pt(767, 174), image.Pt(639, 174)},
	} {
		t.Run(theme.name, func(t *testing.T) {
			reference := syntheticWallpaper(theme.wallpaper)
			current := clone(reference)
			fill(current, image.Rect(600, 8, 700, 24), color.RGBA{255, 255, 255, 0xff}) // clock tick
			fill(current, theme.bounds, theme.banner)
			banner, found := locateNotificationBanner(reference, current)
			if !found || banner != theme.bounds {
				t.Fatalf("banner = %v %t, want %v", banner, found, theme.bounds)
			}
			if got := notificationActionPoint(banner, 2, 0); got != theme.allow {
				t.Fatalf("allow = %v, want %v", got, theme.allow)
			}
			if got := notificationActionPoint(banner, 2, 1); got != theme.decline {
				t.Fatalf("decline = %v, want %v", got, theme.decline)
			}
			if got := notificationActionPoint(banner, 1, 0); got != theme.op {
				t.Fatalf("single action = %v, want %v", got, theme.op)
			}
		})
	}
}

func TestLocateNotificationBannerIgnoresSmallChanges(t *testing.T) {
	reference := syntheticWallpaper(color.RGBA{60, 20, 50, 0xff})
	if _, found := locateNotificationBanner(reference, clone(reference)); found {
		t.Fatal("identical desktop reported a banner")
	}
	pointer := clone(reference)
	fill(pointer, image.Rect(640, 200, 652, 220), color.RGBA{255, 255, 255, 0xff})
	if _, found := locateNotificationBanner(reference, pointer); found {
		t.Fatal("a pointer-sized change was reported as a banner")
	}
	window := clone(reference)
	fill(window, image.Rect(66, 32, 1280, 800), color.RGBA{48, 10, 36, 0xff})
	if _, found := locateNotificationBanner(reference, window); found {
		t.Fatal("a maximized window was reported as a banner")
	}
}

// debian12-arm64-dgx21-assistance-10: GNOME 43's action-less "Remote assistance
// ended" banner is 499x77, so it was not a banner, waitNoBanner never nudged it
// away on the idle seat, and the next consent prompt stayed queued behind it.
func TestLocateNotificationBannerFindsActionlessGNOME43Banner(t *testing.T) {
	reference := syntheticWallpaper(color.RGBA{0, 80, 90, 0xff})
	ended := clone(reference)
	bounds := image.Rect(390, 36, 889, 113)
	fill(ended, bounds, color.RGBA{64, 64, 64, 0xff})
	if banner, found := locateNotificationBanner(reference, ended); !found || banner != bounds {
		t.Fatalf("ended banner = %v %t, want %v", banner, found, bounds)
	}
}

// syntheticPortalDialog draws a GNOME 46/50 share dialog: the RemoteDesktop
// switch, when present, sits first under the header.
func syntheticPortalDialog(wallpaper color.RGBA, dialog image.Rectangle, accent bool) *image.RGBA {
	img := syntheticDialogFrame(wallpaper, dialog)
	// Header text, the switch row border and the monitor preview's black bar.
	fill(img, image.Rect(dialog.Min.X+260, dialog.Min.Y+15, dialog.Min.X+390, dialog.Min.Y+30), color.RGBA{40, 40, 40, 0xff})
	fill(img, image.Rect(dialog.Min.X+42, dialog.Min.Y+78, dialog.Max.X-42, dialog.Min.Y+80), color.RGBA{233, 84, 32, 0xff})
	fill(img, image.Rect(dialog.Min.X+222, dialog.Min.Y+264, dialog.Max.X-218, dialog.Min.Y+274), color.RGBA{0, 0, 0, 0xff})
	syntheticSwitch(img, portalSwitchCandidates(dialog)[0], color.RGBA{250, 250, 250, 0xff}, color.RGBA{233, 84, 32, 0xff}, accent)
	return img
}

// syntheticGNOME43Dialog draws xdg-desktop-portal-gnome 43's 500x300
// RemoteDesktop dialog (debian12-arm64-dgx21-assistance-04): a selected
// monitor row with a blue focus border, then the white "Allow remote
// interaction" row whose grey switch track sits at the bottom candidate.
// Without the switch it is the shorter ScreenCast dialog.
func syntheticGNOME43Dialog(wallpaper color.RGBA, dialog image.Rectangle, withSwitch, accent bool) *image.RGBA {
	img := syntheticDialogFrame(wallpaper, dialog)
	monitor := image.Rect(dialog.Min.X+32, dialog.Min.Y+110, dialog.Max.X-32, dialog.Min.Y+162)
	fill(img, monitor, color.RGBA{235, 235, 235, 0xff})
	fill(img, image.Rect(monitor.Min.X, monitor.Min.Y, monitor.Max.X, monitor.Min.Y+2), color.RGBA{131, 173, 225, 0xff})
	fill(img, image.Rect(monitor.Max.X-28, monitor.Min.Y+20, monitor.Max.X-16, monitor.Min.Y+30), color.RGBA{40, 40, 40, 0xff})
	if withSwitch {
		row := image.Rect(dialog.Min.X+32, dialog.Max.Y-105, dialog.Max.X-32, dialog.Max.Y-51)
		fill(img, row, color.RGBA{255, 255, 255, 0xff})
		syntheticSwitch(img, portalSwitchCandidates(dialog)[1], color.RGBA{255, 255, 255, 0xff}, color.RGBA{53, 132, 228, 0xff}, accent)
	}
	return img
}

func syntheticDialogFrame(wallpaper color.RGBA, dialog image.Rectangle) *image.RGBA {
	img := syntheticWallpaper(wallpaper)
	fill(img, dialog, color.RGBA{250, 250, 250, 0xff})
	// Rounded corners: the first and last rows are shorter on both sides.
	for i := range 10 {
		inset := 10 - i
		fill(img, image.Rect(dialog.Min.X, dialog.Min.Y+i, dialog.Min.X+inset, dialog.Min.Y+i+1), wallpaper)
		fill(img, image.Rect(dialog.Max.X-inset, dialog.Min.Y+i, dialog.Max.X, dialog.Min.Y+i+1), wallpaper)
		fill(img, image.Rect(dialog.Min.X, dialog.Max.Y-1-i, dialog.Min.X+inset, dialog.Max.Y-i), wallpaper)
		fill(img, image.Rect(dialog.Max.X-inset, dialog.Max.Y-1-i, dialog.Max.X, dialog.Max.Y-i), wallpaper)
	}
	return img
}

func syntheticSwitch(img *image.RGBA, centre image.Point, knob, accentTrack color.RGBA, accent bool) {
	track := color.RGBA{225, 225, 225, 0xff}
	if accent {
		track = accentTrack
	}
	fill(img, image.Rect(centre.X-22, centre.Y-12, centre.X+22, centre.Y+12), track)
	fill(img, image.Rect(centre.X+4, centre.Y-9, centre.X+20, centre.Y+9), knob)
}

func TestLocatePortalDialog(t *testing.T) {
	for _, theme := range []struct {
		name      string
		wallpaper color.RGBA
		dialog    image.Rectangle
		share     image.Point
		toggle    image.Point
		draw      func(color.RGBA, image.Rectangle, bool) *image.RGBA
	}{
		{"ubuntu", color.RGBA{60, 20, 50, 0xff}, image.Rect(343, 166, 1003, 666), image.Pt(959, 188), image.Pt(925, 271), syntheticPortalDialog},
		{"fedora", color.RGBA{0, 60, 200, 0xff}, image.Rect(310, 166, 970, 666), image.Pt(926, 188), image.Pt(892, 271), syntheticPortalDialog},
		{"gnome43", color.RGBA{0, 80, 90, 0xff}, image.Rect(390, 266, 890, 566), image.Pt(846, 288), image.Pt(820, 488), func(wallpaper color.RGBA, dialog image.Rectangle, accent bool) *image.RGBA {
			return syntheticGNOME43Dialog(wallpaper, dialog, true, accent)
		}},
	} {
		t.Run(theme.name, func(t *testing.T) {
			img := theme.draw(theme.wallpaper, theme.dialog, false)
			dialog, found := locatePortalDialog(img)
			if !found || dialog.Min.X != theme.dialog.Min.X || dialog.Max.X != theme.dialog.Max.X || dialog.Min.Y < theme.dialog.Min.Y || dialog.Min.Y > theme.dialog.Min.Y+8 || dialog.Max.Y > theme.dialog.Max.Y || dialog.Max.Y < theme.dialog.Max.Y-8 {
				t.Fatalf("dialog = %v %t, want ~%v", dialog, found, theme.dialog)
			}
			if got := portalShareButton(theme.dialog); got != theme.share {
				t.Fatalf("share = %v, want %v", got, theme.share)
			}
			toggle, found := portalControlSwitch(img, theme.dialog)
			if !found || toggle != theme.toggle {
				t.Fatalf("switch = %v %t, want %v", toggle, found, theme.toggle)
			}
			if portalSwitchOn(img, toggle) {
				t.Fatal("neutral switch reported on")
			}
			if !portalSwitchOn(theme.draw(theme.wallpaper, theme.dialog, true), toggle) {
				t.Fatal("accent switch reported off")
			}
		})
	}
}

func TestLocatePortalDialogRejectsDesktopWithoutDialog(t *testing.T) {
	img := syntheticWallpaper(color.RGBA{60, 20, 50, 0xff})
	if _, found := locatePortalDialog(img); found {
		t.Fatal("dialog found on a bare desktop")
	}
	// A light full-width strip is not a centred dialog.
	fill(img, image.Rect(0, 300, 1280, 360), color.RGBA{250, 250, 250, 0xff})
	if _, found := locatePortalDialog(img); found {
		t.Fatal("light strip reported as a dialog")
	}
}

func TestCentreChanged(t *testing.T) {
	reference := syntheticWallpaper(color.RGBA{0, 60, 200, 0xff})
	if centreChanged(reference, clone(reference)) {
		t.Fatal("unchanged centre reported a window")
	}
	window := clone(reference)
	fill(window, image.Rect(275, 148, 1005, 685), color.RGBA{30, 30, 32, 0xff})
	if !centreChanged(reference, window) {
		t.Fatal("terminal window over the centre not observed")
	}
}

// elcapture2-rocky9-x86 failed "guest window did not appear" with the terminal
// open at the centre: Rocky 9's dark gnome-terminal over its navy wallpaper
// differed by more than 48 only on the wallpaper's grey stripes.
func TestCentreChangedDarkWindowOnDarkWallpaper(t *testing.T) {
	reference := image.NewRGBA(image.Rect(0, 0, 1280, 800))
	fill(reference, reference.Bounds(), color.RGBA{8, 19, 29, 0xff})
	// A grey stripe across 36% of the central 240x240 square.
	fill(reference, image.Rect(520, 280, 760, 366), color.RGBA{90, 90, 95, 0xff})
	if centreChanged(reference, clone(reference)) {
		t.Fatal("unchanged centre reported a window")
	}
	window := clone(reference)
	fill(window, image.Rect(342, 136, 932, 591), color.RGBA{29, 29, 27, 0xff})
	if !centreChanged(reference, window) {
		t.Fatal("dark terminal window over the centre not observed")
	}
}

// allow completes consent in one step, so it must tell a Control request's
// RemoteDesktop dialog from a view-only ScreenCast dialog without the server.
func TestPortalHasControlSwitchDistinguishesRequestMode(t *testing.T) {
	wallpaper, bounds := color.RGBA{60, 20, 50, 0xff}, image.Rect(343, 166, 1003, 666)
	for _, accent := range []bool{false, true} {
		img := syntheticPortalDialog(wallpaper, bounds, accent)
		dialog, found := locatePortalDialog(img)
		if _, control := portalControlSwitch(img, dialog); !found || !control {
			t.Fatalf("RemoteDesktop dialog (switch on=%t) not recognised: %v %t", accent, dialog, found)
		}
	}
	view := syntheticPortalDialog(wallpaper, bounds, false)
	centre := portalSwitchCandidates(bounds)[0]
	fill(view, image.Rect(centre.X-22, centre.Y-12, centre.X+22, centre.Y+12), color.RGBA{250, 250, 250, 0xff})
	dialog, found := locatePortalDialog(view)
	if toggle, control := portalControlSwitch(view, dialog); !found || control {
		t.Fatalf("ScreenCast dialog reported a remote interaction switch at %v: %v %t", toggle, dialog, found)
	}
}

// debian12-arm64-dgx21-assistance-03/-04 clicked GNOME 46's switch offset on
// GNOME 43, which landed on the selected monitor row, and timed out waiting
// for the switch. GNOME 43 lists monitors first and its view-only ScreenCast
// dialog is shorter than 300 pixels.
func TestGNOME43PortalSwitchFollowsMonitorList(t *testing.T) {
	wallpaper := color.RGBA{0, 80, 90, 0xff}
	control := syntheticGNOME43Dialog(wallpaper, image.Rect(390, 266, 890, 566), true, false)
	dialog, found := locatePortalDialog(control)
	toggle, hasSwitch := portalControlSwitch(control, dialog)
	if !found || !hasSwitch || toggle != image.Pt(820, 488) {
		t.Fatalf("GNOME 43 RemoteDesktop switch = %v %t in %v %t, want (820,488)", toggle, hasSwitch, dialog, found)
	}
	view := syntheticGNOME43Dialog(wallpaper, image.Rect(390, 300, 890, 513), false, false)
	dialog, found = locatePortalDialog(view)
	if !found {
		t.Fatal("GNOME 43 ScreenCast dialog not located")
	}
	if toggle, hasSwitch := portalControlSwitch(view, dialog); hasSwitch {
		t.Fatalf("GNOME 43 ScreenCast dialog reported a switch at %v", toggle)
	}
}

// syntheticGNOME41Dialog draws xdg-desktop-portal-gnome 41's share dialog as
// observed on Rocky Linux 9.8 (rocky98-arm64-dgx20-assistance-01): a 47 px
// header whose Share label is greyed while nothing is selected, a framed
// monitor list under its heading and, in the RemoteDesktop dialog, a framed
// keyboard/pointer list ending 32 px above the edge. Selected rows show the
// Adwaita accent.
func syntheticGNOME41Dialog(wallpaper color.RGBA, dialog image.Rectangle, control bool, selected map[string]bool, shareSensitive bool) *image.RGBA {
	img := syntheticDialogFrame(wallpaper, dialog)
	background, border, row, accent := color.RGBA{245, 245, 245, 0xff}, color.RGBA{200, 200, 200, 0xff}, color.RGBA{255, 255, 255, 0xff}, color.RGBA{53, 132, 228, 0xff}
	fill(img, image.Rect(dialog.Min.X+10, dialog.Min.Y+47, dialog.Max.X-10, dialog.Max.Y-10), background)
	fill(img, image.Rect(dialog.Min.X+28, dialog.Min.Y+17, dialog.Min.X+64, dialog.Min.Y+27), color.RGBA{50, 50, 50, 0xff})
	label := color.RGBA{148, 148, 148, 0xff}
	if shareSensitive {
		label = color.RGBA{50, 50, 50, 0xff}
	}
	fill(img, image.Rect(dialog.Max.X-62, dialog.Min.Y+17, dialog.Max.X-26, dialog.Min.Y+27), label)
	list := func(borders []int, names []string) {
		for i, name := range names {
			interior := row
			if selected[name] {
				interior = accent
			}
			fill(img, image.Rect(dialog.Min.X+32, borders[i], dialog.Max.X-32, borders[i+1]), interior)
			fill(img, image.Rect(dialog.Min.X+dialog.Dx()/2-40, (borders[i]+borders[i+1])/2-6, dialog.Min.X+dialog.Dx()/2+40, (borders[i]+borders[i+1])/2+6), color.RGBA{30, 30, 30, 0xff})
		}
		for _, y := range borders {
			fill(img, image.Rect(dialog.Min.X+32, y, dialog.Max.X-32, y+1), border)
		}
	}
	list([]int{dialog.Min.Y + 122, dialog.Min.Y + 170}, []string{"monitor"})
	if control {
		list([]int{dialog.Max.Y - 129, dialog.Max.Y - 81, dialog.Max.Y - 33}, []string{"keyboard", "pointer"})
	}
	return img
}

// rocky98-arm64-dgx20-assistance-01 stopped at "control request opened a
// portal dialog without a remote interaction switch": GNOME 40's portal asks
// for a monitor and device rows instead, and its Share stays insensitive until
// they are selected. Row centres are the measured Rocky Linux 9.8 ones.
func TestGNOME41PortalRowsSelectEveryGrant(t *testing.T) {
	wallpaper, bounds := color.RGBA{20, 40, 80, 0xff}, image.Rect(390, 215, 890, 617)
	control := syntheticGNOME41Dialog(wallpaper, bounds, true, nil, false)
	dialog, found := locatePortalDialog(control)
	if !found || dialog.Min.X != bounds.Min.X || dialog.Max.X != bounds.Max.X {
		t.Fatalf("GNOME 41 RemoteDesktop dialog = %v %t, want ~%v", dialog, found, bounds)
	}
	dialog = bounds
	if toggle, found := portalControlSwitch(control, dialog); found {
		t.Fatalf("GNOME 41 dialog reported a remote interaction switch at %v", toggle)
	}
	rows, ok := gnome41PortalRows(control, dialog, true)
	want := []portalRow{{"monitor", image.Pt(640, 361)}, {"keyboard", image.Pt(640, 512)}, {"pointer", image.Pt(640, 560)}}
	if !ok || !slices.Equal(rows, want) {
		t.Fatalf("GNOME 41 rows = %v %t, want %v", rows, ok, want)
	}
	if portalShareSensitive(control, dialog) {
		t.Fatal("greyed Share reported sensitive")
	}
	for _, row := range rows {
		if portalRowSelected(control, dialog, row.centre) {
			t.Fatalf("unselected %s row reported selected", row.name)
		}
	}
	chosen := syntheticGNOME41Dialog(wallpaper, bounds, true, map[string]bool{"monitor": true, "keyboard": true, "pointer": true}, true)
	if rows, ok := gnome41PortalRows(chosen, dialog, true); !ok || len(rows) != 3 {
		t.Fatalf("selected rows no longer located: %v %t", rows, ok)
	}
	for _, row := range rows {
		if !portalRowSelected(chosen, dialog, row.centre) {
			t.Fatalf("selected %s row reported unselected", row.name)
		}
	}
	if !portalShareSensitive(chosen, dialog) {
		t.Fatal("dark Share label reported insensitive")
	}
	view := syntheticGNOME41Dialog(wallpaper, image.Rect(390, 300, 890, 560), false, nil, false)
	if rows, ok := gnome41PortalRows(view, image.Rect(390, 300, 890, 560), false); !ok || !slices.Equal(rows, []portalRow{{"monitor", image.Pt(640, 446)}}) {
		t.Fatalf("GNOME 41 ScreenCast monitor row = %v %t", rows, ok)
	}
	if _, ok := gnome41PortalRows(view, image.Rect(390, 300, 890, 560), true); ok {
		t.Fatal("ScreenCast dialog reported keyboard and pointer rows")
	}
}

// Newer portals keep their switch flow: their dialogs never match the GNOME 41
// row frames, and their Share is sensitive without a selection.
func TestGNOME41PortalRowsRejectNewerDialogs(t *testing.T) {
	for name, img := range map[string]*image.RGBA{
		"gnome46-control": syntheticPortalDialog(color.RGBA{60, 20, 50, 0xff}, image.Rect(343, 166, 1003, 666), false),
		"gnome43-control": syntheticGNOME43Dialog(color.RGBA{0, 80, 90, 0xff}, image.Rect(390, 266, 890, 566), true, false),
		"gnome43-view":    syntheticGNOME43Dialog(color.RGBA{0, 80, 90, 0xff}, image.Rect(390, 300, 890, 513), false, false),
	} {
		dialog, found := locatePortalDialog(img)
		if !found {
			t.Fatalf("%s: dialog not located", name)
		}
		for _, control := range []bool{false, true} {
			if rows, ok := gnome41PortalRows(img, dialog, control); ok {
				t.Errorf("%s: GNOME 41 rows %v located in a newer dialog", name, rows)
			}
		}
		if !portalShareSensitive(img, dialog) {
			t.Errorf("%s: Share reported insensitive", name)
		}
	}
}

func TestPortalMonitorTilesRequireTwoDistinctChoices(t *testing.T) {
	dialog := image.Rect(300, 150, 980, 650)
	img := image.NewRGBA(image.Rect(0, 0, 1280, 800))
	fill(img, dialog, color.RGBA{250, 250, 250, 255})
	left, right := image.Rect(360, 390, 620, 395), image.Rect(650, 390, 900, 395)
	fill(img, left, color.RGBA{204, 204, 204, 255})
	if _, found := portalMonitorTiles(img, dialog); found {
		t.Fatal("one monitor was treated as two choices")
	}
	fill(img, right, color.RGBA{204, 204, 204, 255})
	borders, found := portalMonitorTiles(img, dialog)
	if !found {
		t.Fatal("two native-style monitor borders not located")
	}
	if portalMonitorSelected(img, borders[0]) {
		t.Fatal("neutral monitor border was treated as consent")
	}
	fill(img, left, color.RGBA{30, 90, 220, 255})
	if !portalMonitorSelected(img, borders[0]) || portalMonitorSelected(img, borders[1]) {
		t.Fatal("selected monitor state crossed to the other head")
	}
	fill(img, right, color.RGBA{30, 90, 220, 255})
	if !portalMonitorSelected(img, borders[1]) {
		t.Fatal("second selected border not detected")
	}
}

// The real GNOME 50 (Fedora 44 aarch64, fedora44arm-tier1-23) and GNOME 46
// (Ubuntu 24.04 amd64, ubuntu24-tier1-22) monitors dialogs, cropped to the
// located dialog: the 15" primary-head tile is wider than the 13" one, carries
// the top bar under its border, and both borders have rounded corners, so no
// two rows share both extents.
func TestPortalMonitorTilesLocateUnequalNativeChoices(t *testing.T) {
	for _, test := range []struct {
		file   string
		dialog image.Rectangle
		want   [2]image.Rectangle
	}{
		{"portal-monitors-fedora44-aarch64-310x166.png", image.Rect(310, 166, 970, 666), [2]image.Rectangle{image.Rect(373, 405, 660, 409), image.Rect(681, 405, 908, 410)}},
		{"portal-monitors-ubuntu2404-amd64-343x166.png", image.Rect(343, 166, 1003, 666), [2]image.Rectangle{image.Rect(408, 406, 693, 410), image.Rect(714, 406, 939, 411)}},
	} {
		file, err := os.Open(filepath.Join("testdata", test.file))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := png.Decode(file)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
		img := image.NewRGBA(test.dialog)
		draw.Draw(img, img.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
		borders, found := portalMonitorTiles(img, test.dialog)
		if !found || borders != test.want {
			t.Fatalf("%s: monitor choices = %v %t, want %v", test.file, borders, found, test.want)
		}
		if portalMonitorSelected(img, borders[0]) || portalMonitorSelected(img, borders[1]) {
			t.Fatalf("%s: unselected neutral border treated as consent", test.file)
		}
		fill(img, borders[1], color.RGBA{53, 132, 228, 255})
		if portalMonitorSelected(img, borders[0]) || !portalMonitorSelected(img, borders[1]) {
			t.Fatalf("%s: selecting the second choice crossed heads", test.file)
		}
	}
}
