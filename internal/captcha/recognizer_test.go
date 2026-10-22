package captcha

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
	"sync"
	"testing"
)

// constantModel wins class `pick` for any input, which makes the whole
// pipeline — decode, denoise, segment, normalize, classify — observable
// without a trained model.
func constantModel(pick int, alphabet string) spec {
	s := defaultSpec()
	s.alphabet = alphabet
	s.fc2W = make([]float32, len(alphabet)*denseUnits)
	s.fc2B = make([]float32, len(alphabet))
	s.fc2B[pick] = 1
	return s
}

func TestRecognizeReadsOneCharacterPerSlot(t *testing.T) {
	s := constantModel(1, "xy")
	r := loadSpec(t, s)
	got, err := r.Recognize(drawCaptcha(t, s, s.slots))
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("y", s.slots) {
		t.Fatalf("recognized %q, want %q", got, strings.Repeat("y", s.slots))
	}
}

// Case folding belongs to the model: the alphabet is an index table and may
// repeat a byte, so a 2-class model can map both classes to one character.
func TestAlphabetMayFoldClassesOntoOneCharacter(t *testing.T) {
	for _, pick := range []int{0, 1} {
		s := constantModel(pick, "aa")
		r := loadSpec(t, s)
		got, err := r.Recognize(drawCaptcha(t, s, s.slots))
		if err != nil {
			t.Fatal(err)
		}
		if got != strings.Repeat("a", s.slots) {
			t.Fatalf("class %d recognized %q", pick, got)
		}
	}
}

func TestRecognizeRejectsForeignImages(t *testing.T) {
	s := constantModel(0, "ab")
	r := loadSpec(t, s)
	if w, h := r.Size(); w != s.width || h != s.height {
		t.Fatalf("Size reported %dx%d, model declares %dx%d", w, h, s.width, s.height)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not a png", []byte("certainly not a png")},
		{"truncated png", drawCaptcha(t, s, s.slots)[:40]},
	} {
		if _, err := r.Recognize(tc.data); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	wrong := s
	wrong.width, wrong.height = s.width+8, s.height
	if _, err := r.Recognize(drawCaptcha(t, wrong, 2)); err == nil {
		t.Fatal("image of the wrong size accepted")
	}
	blank := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			blank.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, blank); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Recognize(buf.Bytes()); err == nil {
		t.Fatal("an image with no foreground produced a reading")
	}
}

// A colour running wider than noiseRun is an interference line and must not
// become a character of its own.
func TestRecognizeDropsWideInterferenceLines(t *testing.T) {
	s := constantModel(0, "ab")
	r := loadSpec(t, s)
	img := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			img.Set(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	for g := 0; g < s.slots; g++ {
		left := g*(s.width/s.slots) + 4
		for y := 8; y < 24; y++ {
			for x := left; x < left+8; x++ {
				img.Set(x, y, color.RGBA{0, 0, 0, 255})
			}
		}
	}
	// One distinct colour spanning the whole width: wider than noiseRun.
	for x := 0; x < s.width; x++ {
		img.Set(x, s.height/2, color.RGBA{10, 200, 10, 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	got, err := r.Recognize(buf.Bytes())
	if err != nil {
		t.Fatalf("interference line defeated segmentation: %v", err)
	}
	if len(got) != s.slots {
		t.Fatalf("recognized %q, want %d characters", got, s.slots)
	}
}

func TestRecognizeIsConcurrentAndReusesBuffers(t *testing.T) {
	s := constantModel(1, "xy")
	r := loadSpec(t, s)
	data := drawCaptcha(t, s, s.slots)
	want := strings.Repeat("y", s.slots)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := 0; n < 20; n++ {
				got, err := r.Recognize(data)
				if err != nil || got != want {
					t.Errorf("concurrent recognition returned %q, %v", got, err)
					return
				}
			}
		}()
	}
	group.Wait()
}

func TestReadPixelsHandlesBothImageLayouts(t *testing.T) {
	s := defaultSpec()
	r := loadSpec(t, s)
	rgba := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	paletted := image.NewPaletted(image.Rect(0, 0, s.width, s.height), color.Palette{
		color.RGBA{255, 255, 255, 255}, color.RGBA{7, 11, 13, 255},
	})
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			c := color.RGBA{uint8(x * 3 % 256), uint8(y * 5 % 256), uint8((x + y) % 256), 255}
			rgba.Set(x, y, c)
			paletted.Set(x, y, color.RGBA{7, 11, 13, 255})
		}
	}
	direct := make([]uint32, s.width*s.height)
	r.readPixels(rgba, direct)
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			want := uint32(uint8(x*3%256))<<16 | uint32(uint8(y*5%256))<<8 | uint32(uint8((x+y)%256))
			if got := direct[y*s.width+x]; got != want {
				t.Fatalf("RGBA pixel (%d,%d): got %06x want %06x", x, y, got, want)
			}
		}
	}
	converted := make([]uint32, s.width*s.height)
	r.readPixels(paletted, converted)
	if converted[0] != 0x070b0d {
		t.Fatalf("paletted pixel: got %06x want 070b0d", converted[0])
	}
}

func TestNormalizeMatchesBilinearSampling(t *testing.T) {
	s := defaultSpec()
	r := loadSpec(t, s)
	src := make([]bool, s.width*s.height)
	for y := 0; y < s.height; y++ {
		for x := 0; x < s.width; x++ {
			src[y*s.width+x] = (x*7+y*3)%5 < 2
		}
	}
	region := span{3, 31}
	top, bottom := 2, 29
	var dst [cell * cell]float32
	r.normalize(&dst, src, region, top, bottom)

	width, height := region.end-region.start+1, bottom-top+1
	scaledW, scaledH := width, height
	if size := max(width, height); size > s.inset {
		scale := float64(s.inset) / float64(size)
		scaledW = max(1, int(math.Round(float64(width)*scale)))
		scaledH = max(1, int(math.Round(float64(height)*scale)))
	}
	offsetX, offsetY := (cell-scaledW)/2, (cell-scaledH)/2
	scaleX, scaleY := float64(width)/float64(scaledW), float64(height)/float64(scaledH)
	at := func(x, y int) float32 {
		if src[y*s.width+x] {
			return 1
		}
		return 0
	}
	var want [cell * cell]float32
	for y := 0; y < scaledH; y++ {
		vy := max(0, min(float64(height-1), (float64(y)+0.5)*scaleY-0.5))
		up, down := int(vy)+top, min(int(vy)+1, height-1)+top
		fy := float32(vy - float64(int(vy)))
		for x := 0; x < scaledW; x++ {
			vx := max(0, min(float64(width-1), (float64(x)+0.5)*scaleX-0.5))
			left, right := int(vx)+region.start, min(int(vx)+1, width-1)+region.start
			fx := float32(vx - float64(int(vx)))
			v := (1-fx)*(1-fy)*at(left, up) + fx*(1-fy)*at(right, up) +
				(1-fx)*fy*at(left, down) + fx*fy*at(right, down)
			if v > 0.5 {
				want[(offsetY+y)*cell+offsetX+x] = 1
			}
		}
	}
	if dst != want {
		t.Fatal("normalize does not match independent bilinear sampling")
	}
}

func FuzzRecognize(f *testing.F) {
	s := constantModel(0, "ab")
	r, err := Load(writeModel(f, s))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(drawCaptcha(f, s, s.slots))
	f.Add([]byte("MCNN"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := r.Recognize(data)
		if err == nil && len(got) != s.slots {
			t.Fatalf("accepted input produced %q", got)
		}
	})
}

func BenchmarkRecognize(b *testing.B) {
	s := constantModel(0, "ab")
	s.randomWeights(99)
	r := loadSpec(b, s)
	data := drawCaptcha(b, s, s.slots)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Recognize(data); err != nil {
			b.Fatal(err)
		}
	}
}

// PNG decoding allocates the image, so only the stage after it can be
// allocation free. These two benchmarks separate the costs.
func BenchmarkRecognizeImage(b *testing.B) {
	s := constantModel(0, "ab")
	s.randomWeights(99)
	r := loadSpec(b, s)
	img, err := png.Decode(bytes.NewReader(drawCaptcha(b, s, s.slots)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.recognizeImage(img); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPredict(b *testing.B) {
	s := defaultSpec()
	s.randomWeights(99)
	r := loadSpec(b, s)
	var buf activations
	var input [cell * cell]float32
	for i := range input {
		input[i] = float32(i % 2)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.model.predict(&input, &buf)
	}
}

func TestRecognizeImageAllocatesNothing(t *testing.T) {
	s := constantModel(0, "ab")
	r := loadSpec(t, s)
	img, err := png.Decode(bytes.NewReader(drawCaptcha(t, s, s.slots)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.recognizeImage(img); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(50, func() {
		if _, err := r.recognizeImage(img); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Fatalf("recognition after decoding allocated %v times per run", n)
	}
}
