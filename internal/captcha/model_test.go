package captcha

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsMalformedModels(t *testing.T) {
	good := defaultSpec().bytes()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"short header", good[:7]},
		{"truncated", good[:len(good)-4]},
		{"trailing bytes", append(append([]byte(nil), good...), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "m.bin")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("malformed model accepted")
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.bin")); err == nil {
		t.Fatal("missing model accepted")
	}
	for _, offset := range []int{0, 4} {
		bad := append([]byte(nil), good...)
		bad[offset]++
		path := filepath.Join(t.TempDir(), "m.bin")
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("corrupt header byte %d accepted", offset)
		}
	}
}

func TestLoadRejectsGeometryOutsideEngineLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*spec)
	}{
		{"zero width", func(s *spec) { s.width = 0 }},
		{"oversize width", func(s *spec) { s.width = maxImageWidth + 1 }},
		{"oversize height", func(s *spec) { s.height = maxImageHeight + 1 }},
		{"zero slots", func(s *spec) { s.slots = 0; s.fallback = nil }},
		{"oversize inset", func(s *spec) { s.inset = cell + 1 }},
		{"background out of range", func(s *spec) { s.bgMin = 256 }},
		{"noise run past width", func(s *spec) { s.noiseRun = s.width + 1 }},
		{"fallback past width", func(s *spec) { s.fallback = [][2]int{{0, 31}, {32, 999}} }},
		{"inverted fallback", func(s *spec) { s.fallback = [][2]int{{0, 31}, {40, 32}} }},
		{"empty alphabet", func(s *spec) { s.alphabet = ""; s.fc2W = nil; s.fc2B = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := defaultSpec()
			tc.edit(&s)
			if _, err := Load(writeModel(t, s)); err == nil {
				t.Fatal("model outside the engine limits accepted")
			}
		})
	}
}

func TestLoadRejectsForeignTopology(t *testing.T) {
	base := defaultSpec()
	good := base.bytes()
	// Derive the offset rather than hardcoding it: magic, version, the six
	// geometry words, the alphabet length, the alphabet, then the spans.
	offset := 4 + 4 + 6*4 + 4 + len(base.alphabet) + base.slots*8
	for i := 0; i < 3; i++ {
		bad := append([]byte(nil), good...)
		bad[offset+i*4]++
		path := filepath.Join(t.TempDir(), "m.bin")
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "engine runs") {
			t.Fatalf("topology field %d: %v", i, err)
		}
	}
}

// predict must agree with the layer definitions for any weights, so random
// ones prove the fused kernel rather than a particular trained model.
func TestPredictMatchesLayerDefinitions(t *testing.T) {
	s := defaultSpec()
	s.randomWeights(42)
	r := loadSpec(t, s)
	m := r.model
	rng := rand.New(rand.NewPCG(7, 11))
	var buf activations
	var input [cell * cell]float32
	for n := 0; n < 24; n++ {
		for i := range input {
			switch n % 3 {
			case 0:
				input[i] = float32(rng.Float64())
			case 1:
				input[i] = float32(rng.IntN(2))
			case 2:
				input[i] = 0
				if rng.IntN(8) == 0 {
					input[i] = 1
				}
			}
		}
		class := m.predict(&input, &buf)
		for oc, bias := range m.fc1B {
			want := bias
			for i, v := range buf.flat {
				want += v * m.fc1W[oc*flat+i]
			}
			if want < 0 {
				want = 0
			}
			if got := buf.dense[oc]; got != want {
				t.Fatalf("input %d dense neuron %d: got %g want %g", n, oc, got, want)
			}
		}
		best, bestLogit := 0, float32(0)
		for oc := 0; oc < m.classes; oc++ {
			sum := m.fc2B[oc]
			for i, v := range buf.dense {
				sum += v * m.fc2W[oc*denseUnits+i]
			}
			if oc == 0 || sum > bestLogit {
				best, bestLogit = oc, sum
			}
		}
		if int(class) != best {
			t.Fatalf("input %d: predicted class %d, definition says %d", n, class, best)
		}
	}
}

func TestConvPoolMatchesDefinition(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 5))
	const size, channels, filters = 8, 2, 3
	stride, outStride := size+2, size/2+2
	src := make([]float32, channels*stride*stride)
	weights := make([]float32, filters*channels*9)
	biases := make([]float32, filters)
	for i := range src {
		src[i] = float32(rng.Float64()*2 - 1)
	}
	for i := range weights {
		weights[i] = float32(rng.Float64()*2 - 1)
	}
	for i := range biases {
		biases[i] = float32(rng.Float64()*2 - 1)
	}
	// Padding must stay zero for the kernel's bounds-free indexing to be valid.
	for ic := 0; ic < channels; ic++ {
		for i := 0; i < stride; i++ {
			src[ic*stride*stride+i] = 0
			src[ic*stride*stride+(stride-1)*stride+i] = 0
			src[ic*stride*stride+i*stride] = 0
			src[ic*stride*stride+i*stride+stride-1] = 0
		}
	}
	dst := make([]float32, filters*outStride*outStride)
	convPool(src, dst, size, channels, weights, biases)

	conv := func(oc, y, x int) float32 {
		sum := biases[oc]
		for ic := 0; ic < channels; ic++ {
			for ky := 0; ky < 3; ky++ {
				for kx := 0; kx < 3; kx++ {
					sum += src[ic*stride*stride+(y+ky)*stride+x+kx] * weights[(oc*channels+ic)*9+ky*3+kx]
				}
			}
		}
		return sum
	}
	for oc := 0; oc < filters; oc++ {
		for y := 0; y < size/2; y++ {
			for x := 0; x < size/2; x++ {
				want := conv(oc, y*2, x*2)
				for _, v := range []float32{conv(oc, y*2, x*2+1), conv(oc, y*2+1, x*2), conv(oc, y*2+1, x*2+1)} {
					if v > want {
						want = v
					}
				}
				if want < 0 {
					want = 0
				}
				if got := dst[oc*outStride*outStride+(y+1)*outStride+x+1]; got != want {
					t.Fatalf("filter %d at (%d,%d): got %g want %g", oc, y, x, got, want)
				}
			}
		}
	}
}
