package captcha

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"math"
	"sync"
)

type span struct{ start, end int }

// Recognizer reads the captcha a model was trained for. It is immutable after
// Load and safe for concurrent use; every call takes its buffers from a pool
// and allocates nothing.
type Recognizer struct {
	model    *model
	geometry geometry
}

type buffers struct {
	pixels     [maxImageWidth * maxImageHeight]uint32
	foreground [maxImageWidth * maxImageHeight]bool
	columns    [maxImageWidth]int
	spans      [maxSlots]span
	result     [maxSlots]byte
	cell       [cell * cell]float32
	network    activations
}

var pool = sync.Pool{New: func() any { return new(buffers) }}

// Size reports the image geometry this model accepts.
func (r *Recognizer) Size() (width, height int) {
	return r.geometry.width, r.geometry.height
}

// Recognize decodes a PNG captcha and returns the characters it reads, folded
// to the case the model was trained on.
func (r *Recognizer) Recognize(data []byte) (string, error) {
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("decode captcha PNG header: %w", err)
	}
	if config.Width != r.geometry.width || config.Height != r.geometry.height {
		return "", fmt.Errorf("unsupported captcha size %dx%d: this model reads %dx%d", config.Width, config.Height, r.geometry.width, r.geometry.height)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("decode captcha PNG: %w", err)
	}
	return r.recognizeImage(img)
}

func (r *Recognizer) recognizeImage(img image.Image) (string, error) {
	g := &r.geometry
	if img == nil || img.Bounds().Dx() != g.width || img.Bounds().Dy() != g.height {
		return "", fmt.Errorf("captcha image must be %dx%d", g.width, g.height)
	}
	buf := pool.Get().(*buffers)
	defer pool.Put(buf)
	pixels := buf.pixels[:g.width*g.height]
	r.readPixels(img, pixels)
	columns := buf.columns[:g.width]
	clear(columns)

	// A colour spanning more than noiseRun columns belongs to an interference
	// line. Gateway images use a small discrete palette, bounded here.
	var colours [32]uint32
	var extents [32]span
	count := 0
	for i, rgb := range pixels {
		if r.background(rgb) {
			continue
		}
		x := i % g.width
		found := false
		for c := 0; c < count; c++ {
			if colours[c] == rgb {
				extents[c].start = min(extents[c].start, x)
				extents[c].end = max(extents[c].end, x)
				found = true
				break
			}
		}
		if !found && count < len(colours) {
			colours[count] = rgb
			extents[count] = span{x, x}
			count++
		}
	}
	var noise [32]uint32
	noiseCount := 0
	for c := 0; c < count; c++ {
		if extents[c].end-extents[c].start > g.noiseRun {
			noise[noiseCount] = colours[c]
			noiseCount++
		}
	}
	foreground := buf.foreground[:g.width*g.height]
	for i, rgb := range pixels {
		keep := !r.background(rgb)
		for c := 0; keep && c < noiseCount; c++ {
			keep = rgb != noise[c]
		}
		foreground[i] = keep
		if keep {
			columns[i%g.width]++
		}
	}

	spans := buf.spans[:g.slots]
	found := 0
	for x := 0; x < g.width; {
		if columns[x] == 0 {
			x++
			continue
		}
		start := x
		for x < g.width && columns[x] != 0 {
			x++
		}
		if found < len(spans) {
			spans[found] = span{start, x - 1}
		}
		found++
	}
	if found != g.slots {
		copy(spans, g.fallback[:g.slots])
	}

	result := buf.result[:g.slots]
	for i, s := range spans {
		top, bottom := g.height, -1
		for y := 0; y < g.height; y++ {
			for x := s.start; x <= s.end; x++ {
				if foreground[y*g.width+x] {
					top, bottom = min(top, y), max(bottom, y)
				}
			}
		}
		if bottom < top {
			return "", fmt.Errorf("captcha character %d is empty", i+1)
		}
		r.normalize(&buf.cell, foreground, s, top, bottom)
		result[i] = g.alphabet[r.model.predict(&buf.cell, &buf.network)]
	}
	return string(result), nil
}

func (r *Recognizer) background(rgb uint32) bool {
	m := r.geometry.bgMin
	return rgb>>16 >= m && (rgb>>8)&255 >= m && rgb&255 >= m
}

// readPixels avoids one boxed colour allocation per pixel for the RGBA images
// PNG normally decodes to. Other colour models keep their defined conversion.
func (r *Recognizer) readPixels(img image.Image, dst []uint32) {
	g := &r.geometry
	if rgba, ok := img.(*image.RGBA); ok {
		for y := 0; y < g.height; y++ {
			row := rgba.Pix[y*rgba.Stride : y*rgba.Stride+g.width*4]
			for x := 0; x < g.width; x++ {
				dst[y*g.width+x] = uint32(row[x*4])<<16 | uint32(row[x*4+1])<<8 | uint32(row[x*4+2])
			}
		}
		return
	}
	origin := img.Bounds().Min
	for y := 0; y < g.height; y++ {
		for x := 0; x < g.width; x++ {
			red, green, blue, _ := img.At(x+origin.X, y+origin.Y).RGBA()
			dst[y*g.width+x] = (red>>8)<<16 | (green>>8)<<8 | blue>>8
		}
	}
}

// normalize samples one character straight from the foreground mask into the
// centred glyph cell, without an intermediate crop or resize.
func (r *Recognizer) normalize(dst *[cell * cell]float32, src []bool, s span, top, bottom int) {
	g := &r.geometry
	clear(dst[:])
	width, height := s.end-s.start+1, bottom-top+1
	scaledW, scaledH := width, height
	if size := max(width, height); size > g.inset {
		scale := float64(g.inset) / float64(size)
		scaledW = max(1, int(math.Round(float64(width)*scale)))
		scaledH = max(1, int(math.Round(float64(height)*scale)))
	}
	offsetX, offsetY := (cell-scaledW)/2, (cell-scaledH)/2
	scaleX, scaleY := float64(width)/float64(scaledW), float64(height)/float64(scaledH)
	var left, right [cell]int
	var fx [cell]float32
	for x := 0; x < scaledW; x++ {
		v := max(0, min(float64(width-1), (float64(x)+0.5)*scaleX-0.5))
		left[x], right[x] = int(v)+s.start, min(int(v)+1, width-1)+s.start
		fx[x] = float32(v - float64(int(v)))
	}
	for y := 0; y < scaledH; y++ {
		v := max(0, min(float64(height-1), (float64(y)+0.5)*scaleY-0.5))
		up, down := int(v)+top, min(int(v)+1, height-1)+top
		fy := float32(v - float64(int(v)))
		for x := 0; x < scaledW; x++ {
			v00 := mask(src[up*g.width+left[x]])
			v01 := mask(src[up*g.width+right[x]])
			v10 := mask(src[down*g.width+left[x]])
			v11 := mask(src[down*g.width+right[x]])
			if (1-fx[x])*(1-fy)*v00+fx[x]*(1-fy)*v01+(1-fx[x])*fy*v10+fx[x]*fy*v11 > 0.5 {
				dst[(offsetY+y)*cell+offsetX+x] = 1
			}
		}
	}
}

func mask(v bool) float32 {
	if v {
		return 1
	}
	return 0
}
