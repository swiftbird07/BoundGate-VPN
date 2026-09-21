package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// palette: the Mac app's accent colors, readable on light and dark taskbars
var palette = map[Color]color.NRGBA{
	Gray:  {0x8a, 0x8f, 0x98, 0xff},
	Amber: {0xe8, 0xa3, 0x17, 0xff},
	Green: {0x2e, 0xb8, 0x72, 0xff},
	Red:   {0xe0, 0x4f, 0x4f, 0xff},
}

// Icon is the tray icon for a state as an ICO file (one 32×32 PNG inside,
// which Windows Vista and later read): a disc in the state's color with a
// white gate, an arch over an opening. Drawn here so the program carries
// no image files.
func Icon(c Color) []byte {
	const size, ss = 32, 4 // 4×4 supersampling for smooth edges
	fill := palette[c]
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var disc, gate int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) - size/2
					py := (float64(y) + (float64(sy)+0.5)/ss) - size/2
					if math.Hypot(px, py) > 15.5 {
						continue
					}
					disc++
					if inGate(px, py) {
						gate++
					}
				}
			}
			n := ss * ss
			if disc == 0 {
				continue
			}
			// white over the fill in proportion to the gate's coverage
			w := float64(gate) / float64(disc)
			mix := func(a uint8) uint8 { return uint8(float64(a)*(1-w) + 255*w + 0.5) }
			img.SetNRGBA(x, y, color.NRGBA{mix(fill.R), mix(fill.G), mix(fill.B), uint8(255 * disc / n)})
		}
	}
	var p bytes.Buffer
	_ = png.Encode(&p, img)
	return ico(p.Bytes(), size)
}

// inGate: the white stroke of an arch, 3 px wide, from the base line up to a
// half circle, centered in the disc.
func inGate(x, y float64) bool {
	const r, stroke, base, top = 7.0, 3.0, 8.0, -2.0
	switch {
	case y > base:
		return false
	case y >= top: // the two posts
		return math.Abs(math.Abs(x)-(r-stroke/2)) <= stroke/2
	default: // the arch around (0, top)
		d := math.Hypot(x, y-top)
		return d <= r && d >= r-stroke
	}
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
