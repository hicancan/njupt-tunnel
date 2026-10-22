package captcha

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// The engine is tested against models and images built here, never against a
// real gateway's captcha or a trained model. A synthetic fixture is enough:
// predict, convPool and normalize are checked against their mathematical
// definitions, which holds for any weights.

type spec struct {
	width, height, slots, inset int
	bgMin, noiseRun             int
	alphabet                    string
	fallback                    [][2]int
	conv1W, conv1B              []float32
	conv2W, conv2B              []float32
	fc1W, fc1B                  []float32
	fc2W, fc2B                  []float32
}

// defaultSpec describes a small captcha with zeroed weights. Tests override
// only the fields they care about.
func defaultSpec() spec {
	s := spec{
		width: 64, height: 32, slots: 2, inset: 26,
		bgMin: 250, noiseRun: 40,
		alphabet: "ab",
		fallback: [][2]int{{0, 31}, {32, 63}},
	}
	s.conv1W = make([]float32, conv1Filters*9)
	s.conv1B = make([]float32, conv1Filters)
	s.conv2W = make([]float32, conv2Filters*conv1Filters*9)
	s.conv2B = make([]float32, conv2Filters)
	s.fc1W = make([]float32, denseUnits*flat)
	s.fc1B = make([]float32, denseUnits)
	s.fc2W = make([]float32, len(s.alphabet)*denseUnits)
	s.fc2B = make([]float32, len(s.alphabet))
	return s
}

// randomWeights fills every layer with deterministic pseudo-random values, so
// predict is exercised on a model where no term vanishes.
func (s *spec) randomWeights(seed uint64) {
	rng := rand.New(rand.NewPCG(seed, seed*2+1))
	for _, layer := range [][]float32{s.conv1W, s.conv1B, s.conv2W, s.conv2B, s.fc1W, s.fc1B, s.fc2W, s.fc2B} {
		for i := range layer {
			layer[i] = float32(rng.Float64()*2 - 1)
		}
	}
}

func (s spec) bytes() []byte {
	var b bytes.Buffer
	b.WriteString("MCNN")
	u32 := func(v int) {
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], uint32(v))
		b.Write(raw[:])
	}
	u32(2)
	u32(s.width)
	u32(s.height)
	u32(s.slots)
	u32(s.inset)
	u32(s.bgMin)
	u32(s.noiseRun)
	u32(len(s.alphabet))
	b.WriteString(s.alphabet)
	for _, f := range s.fallback {
		u32(f[0])
		u32(f[1])
	}
	u32(conv1Filters)
	u32(conv2Filters)
	u32(denseUnits)
	for _, layer := range [][]float32{s.conv1W, s.conv1B, s.conv2W, s.conv2B, s.fc1W, s.fc1B, s.fc2W, s.fc2B} {
		for _, v := range layer {
			u32(int(math.Float32bits(v)))
		}
	}
	return b.Bytes()
}

func writeModel(tb testing.TB, s spec) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "model.bin")
	if err := os.WriteFile(path, s.bytes(), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

func loadSpec(tb testing.TB, s spec) *Recognizer {
	tb.Helper()
	r, err := Load(writeModel(tb, s))
	if err != nil {
		tb.Fatal(err)
	}
	return r
}

// drawCaptcha renders one filled block per slot on a white background, which
// is all the segmenter needs: a run of non-background columns per character.
// Each glyph gets its own colour, as a real captcha's small discrete palette
// does; one colour shared by every glyph would span the whole image and be
// discarded as an interference line.
func drawCaptcha(tb testing.TB, s spec, glyphs int) []byte {
	tb.Helper()
	img := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	slot := s.width / glyphs
	for g := 0; g < glyphs; g++ {
		left := g*slot + slot/4
		ink := color.RGBA{uint8(16 + g*32), uint8(32 + g*16), uint8(48 + g*8), 255}
		for y := s.height / 4; y < s.height*3/4; y++ {
			for x := left; x < left+slot/2; x++ {
				img.Set(x, y, ink)
			}
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		tb.Fatal(err)
	}
	return out.Bytes()
}
