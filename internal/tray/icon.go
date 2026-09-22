package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// The tray icon is the mark (docs/DESIGN.md), drawn like the Mac app's menu
// bar icon (apps/macos, MenuBarIcon): two interlocked rounded frames in one
// color that suits the taskbar, as Windows 11's own tray icons are. Connected:
// both frames at full strength. Otherwise the second frame is dimmed, one end
// has no connection (the Mac dashes it; at 16 px dashes crumble, and Windows
// dims what is off, as in its Wi-Fi icon). A dot says what the state wants: yellow for attention (sign
// in, approval, on its way), red when something is broken. Drawn here so the
// program carries no image files.

var (
	glyphOnDark  = color.NRGBA{0xff, 0xff, 0xff, 0xff}
	glyphOnLight = color.NRGBA{0x1c, 0x1c, 0x1c, 0xff}
	dotColor     = map[Color]color.NRGBA{
		Amber: {0xff, 0xcc, 0x00, 0xff}, // the brand's "needs attention"
		Red:   {0xe0, 0x4f, 0x4f, 0xff},
	}
)

// Icon is the tray icon for a state as an ICO file with one PNG of size
// pixels; light is a light taskbar (dark glyph). shown is the size the
// taskbar shows it at: the tray library loads icons at the large icon size
// and the taskbar scales them down, so the stroke is chosen for what is
// finally seen (heavier at 16 and 20 px, as the favicon).
func Icon(c Color, light bool, size, shown int) []byte {
	glyph := glyphOnDark
	if light {
		glyph = glyphOnLight
	}
	var p bytes.Buffer
	_ = png.Encode(&p, drawMark(size, shown, glyph, c))
	return ico(p.Bytes(), size)
}

// A 20-unit square: the Mac's 20×16 menu bar grid, centered vertically.
type rrect struct{ x, y, w, h, r float64 }

var (
	frameA = rrect{1.5, 4, 11, 8, 2.4}
	frameB = rrect{7.5, 9, 11, 8, 2.4}
)

const (
	dotX, dotY    = 16.6, 4.4
	dotR, dotHole = 2.7, 4.1 // the dot, and the gap cut around it
	dimmed        = 0.4      // the second frame's strength when not connected
)

func drawMark(size, shown int, glyph color.NRGBA, c Color) *image.NRGBA {
	const ss = 4 // 4×4 supersampling
	unit := float64(size) / 20
	lw := 1.6 // the Mac's stroke; heavier where the icon is tiny, as the favicon
	if shown <= 20 {
		lw = 2.0
	}
	connected := c == Green
	dot, hasDot := dotColor[c]
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var g, gb, d float64 // coverage: frame A, frame B, dot
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) / unit
					py := (float64(y) + (float64(sy)+0.5)/ss) / unit
					if hasDot {
						r := math.Hypot(px-dotX, py-dotY)
						if r <= dotR {
							d++
							continue
						}
						if r <= dotHole {
							continue
						}
					}
					if frameA.onStroke(px, py, lw) {
						g++
					} else if frameB.onStroke(px, py, lw) {
						gb++
					}
				}
			}
			n := float64(ss * ss)
			g, gb, d = g/n, gb/n, d/n
			if !connected {
				gb *= dimmed
			}
			a := g + gb + d
			if a == 0 {
				continue
			}
			// the dot never overlaps the frames' coverage (the gap), so mixing
			// by share keeps its color clean
			mix := func(gc, dc uint8) uint8 { return uint8((float64(gc)*(g+gb) + float64(dc)*d) / a) }
			img.SetNRGBA(x, y, color.NRGBA{mix(glyph.R, dot.R), mix(glyph.G, dot.G), mix(glyph.B, dot.B), uint8(math.Min(a, 1)*255 + 0.5)})
		}
	}
	return img
}

// onStroke: within half the line width of the rounded rectangle's outline.
func (f rrect) onStroke(px, py, lw float64) bool {
	cx, cy := f.x+f.w/2, f.y+f.h/2
	qx := math.Abs(px-cx) - (f.w/2 - f.r)
	qy := math.Abs(py-cy) - (f.h/2 - f.r)
	outside := math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - f.r
	return math.Abs(outside) <= lw/2
}

// ico wraps one PNG image in an ICO container.
func ico(pngData []byte, size int) []byte {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	w(uint16(0)) // reserved
	w(uint16(1)) // type: icon
	w(uint16(1)) // one image
	d := uint8(size)
	if size >= 256 {
		d = 0
	}
	b.Write([]byte{d, d, 0, 0}) // width, height, no palette, reserved
	w(uint16(1))                // color planes
	w(uint16(32))               // bits per pixel
	w(uint32(len(pngData)))
	w(uint32(6 + 16)) // offset of the image: after header and one entry
	b.Write(pngData)
	return b.Bytes()
}
