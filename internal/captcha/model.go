package captcha

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
)

// The network's shape is the engine: a 3x3 convolution, ReLU and 2x2 pooling
// twice over a square glyph cell, then two dense layers. Everything that
// describes a particular gateway's captcha instead lives in the model file.
const (
	cell         = 32 // the glyph cell the network consumes
	conv1Filters = 8
	conv2Filters = 16
	denseUnits   = 64

	pool1 = cell / 2  // 16
	pool2 = pool1 / 2 // 8
	flat  = conv2Filters * pool2 * pool2

	// Limits the engine imposes on a model file, so every buffer can be a
	// fixed-size array and recognition allocates nothing.
	maxImageWidth  = 320
	maxImageHeight = 96
	maxSlots       = 8
	maxClasses     = 95 // printable ASCII
)

// geometry is the part of a model that describes its target captcha. It is
// read from the file, never compiled in, so a model trained for a different
// gateway needs no code change.
type geometry struct {
	width    int
	height   int
	slots    int
	inset    int // the glyph is scaled to fit inside this many pixels of the cell
	bgMin    uint32
	noiseRun int
	alphabet string
	fallback [maxSlots]span
}

// model holds the trained weights. Shapes are fixed by the engine except the
// output layer, which is as wide as the model's alphabet.
type model struct {
	classes int
	conv1W  [conv1Filters * 9]float32
	conv1B  [conv1Filters]float32
	conv2W  [conv2Filters * conv1Filters * 9]float32
	conv2B  [conv2Filters]float32
	fc1W    [denseUnits * flat]float32
	fc1B    [denseUnits]float32
	fc2W    [maxClasses * denseUnits]float32
	fc2B    [maxClasses]float32
}

// The zero border of each padded activation stays untouched between calls.
// Convolution, ReLU and pooling are fused, so full convolution maps never exist.
type activations struct {
	input [(cell + 2) * (cell + 2)]float32
	conv1 [conv1Filters * (pool1 + 2) * (pool1 + 2)]float32
	conv2 [conv2Filters * (pool2 + 2) * (pool2 + 2)]float32
	flat  [flat]float32
	dense [denseUnits]float32
}

type reader struct {
	data []byte
	at   int
	err  error
}

func (r *reader) u32() int {
	if r.err != nil {
		return 0
	}
	if r.at+4 > len(r.data) {
		r.err = errors.New("captcha model is truncated")
		return 0
	}
	v := binary.LittleEndian.Uint32(r.data[r.at:])
	r.at += 4
	return int(v)
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.at+n > len(r.data) {
		r.err = errors.New("captcha model is truncated")
		return nil
	}
	b := r.data[r.at : r.at+n]
	r.at += n
	return b
}

func (r *reader) floats(dst []float32) {
	for i := range dst {
		if r.err != nil {
			return
		}
		dst[i] = math.Float32frombits(uint32(r.u32()))
	}
}

// Load reads a self-describing captcha model. The file carries the geometry of
// the captcha it was trained on, so this package contains no values belonging
// to any particular gateway.
func Load(path string) (*Recognizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read captcha model: %w", err)
	}
	r := &reader{data: data}
	if string(r.bytes(4)) != "MCNN" {
		return nil, errors.New("not a captcha model file")
	}
	if version := r.u32(); version != 2 {
		return nil, fmt.Errorf("unsupported captcha model version %d, want 2", version)
	}
	var g geometry
	g.width, g.height, g.slots = r.u32(), r.u32(), r.u32()
	g.inset, g.bgMin, g.noiseRun = r.u32(), uint32(r.u32()), r.u32()
	classes := r.u32()
	g.alphabet = string(r.bytes(classes))
	if r.err != nil {
		return nil, r.err
	}
	switch {
	case g.width < 1 || g.width > maxImageWidth || g.height < 1 || g.height > maxImageHeight:
		return nil, fmt.Errorf("captcha model geometry %dx%d exceeds the engine limit %dx%d", g.width, g.height, maxImageWidth, maxImageHeight)
	case g.slots < 1 || g.slots > maxSlots:
		return nil, fmt.Errorf("captcha model declares %d character slots, the engine allows 1..%d", g.slots, maxSlots)
	case g.inset < 1 || g.inset > cell:
		return nil, fmt.Errorf("captcha model inset %d must be within the %d pixel cell", g.inset, cell)
	case g.bgMin > 255:
		return nil, errors.New("captcha model background threshold must be a channel value")
	case g.noiseRun < 1 || g.noiseRun > g.width:
		return nil, errors.New("captcha model noise run must be within the image width")
	case classes < 1 || classes > maxClasses:
		return nil, fmt.Errorf("captcha model declares %d classes, the engine allows 1..%d", classes, maxClasses)
	}
	for i := 0; i < g.slots; i++ {
		start, end := r.u32(), r.u32()
		if r.err == nil && (start < 0 || end < start || end >= g.width) {
			return nil, fmt.Errorf("captcha model fallback span %d is outside the image", i)
		}
		g.fallback[i] = span{start, end}
	}
	m := &model{classes: classes}
	if got, want := r.u32(), conv1Filters; got != want {
		return nil, fmt.Errorf("captcha model has %d first-layer filters, this engine runs %d", got, want)
	}
	if got, want := r.u32(), conv2Filters; got != want {
		return nil, fmt.Errorf("captcha model has %d second-layer filters, this engine runs %d", got, want)
	}
	if got, want := r.u32(), denseUnits; got != want {
		return nil, fmt.Errorf("captcha model has %d dense units, this engine runs %d", got, want)
	}
	r.floats(m.conv1W[:])
	r.floats(m.conv1B[:])
	r.floats(m.conv2W[:])
	r.floats(m.conv2B[:])
	r.floats(m.fc1W[:])
	r.floats(m.fc1B[:])
	r.floats(m.fc2W[:classes*denseUnits])
	r.floats(m.fc2B[:classes])
	if r.err != nil {
		return nil, r.err
	}
	if r.at != len(data) {
		return nil, fmt.Errorf("captcha model has %d trailing bytes", len(data)-r.at)
	}
	return &Recognizer{model: m, geometry: g}, nil
}

func (m *model) predict(input *[cell * cell]float32, buf *activations) byte {
	const stride = cell + 2
	for y := 0; y < cell; y++ {
		copy(buf.input[(y+1)*stride+1:(y+1)*stride+1+cell], input[y*cell:(y+1)*cell])
	}
	convPool(buf.input[:], buf.conv1[:], cell, 1, m.conv1W[:], m.conv1B[:])
	convPool(buf.conv1[:], buf.conv2[:], pool1, conv1Filters, m.conv2W[:], m.conv2B[:])
	const padded = pool2 + 2
	for c := 0; c < conv2Filters; c++ {
		for y := 0; y < pool2; y++ {
			src := c*padded*padded + (y+1)*padded + 1
			copy(buf.flat[c*pool2*pool2+y*pool2:], buf.conv2[src:src+pool2])
		}
	}
	// Interleaving four independent sums lets the CPU overlap accumulation
	// without changing the order of operations within any output neuron.
	for oc := 0; oc < denseUnits; oc += 4 {
		w0 := m.fc1W[oc*flat : (oc+1)*flat]
		w1 := m.fc1W[(oc+1)*flat : (oc+2)*flat]
		w2 := m.fc1W[(oc+2)*flat : (oc+3)*flat]
		w3 := m.fc1W[(oc+3)*flat : (oc+4)*flat]
		a, b, c, d := m.fc1B[oc], m.fc1B[oc+1], m.fc1B[oc+2], m.fc1B[oc+3]
		for i, v := range buf.flat {
			a += v * w0[i]
			b += v * w1[i]
			c += v * w2[i]
			d += v * w3[i]
		}
		buf.dense[oc], buf.dense[oc+1] = max(a, 0), max(b, 0)
		buf.dense[oc+2], buf.dense[oc+3] = max(c, 0), max(d, 0)
	}
	best := 0
	bestLogit := float32(math.Inf(-1))
	for oc := 0; oc < m.classes; oc++ {
		w := m.fc2W[oc*denseUnits : (oc+1)*denseUnits]
		sum := m.fc2B[oc]
		for i, v := range buf.dense {
			sum += v * w[i]
		}
		if sum > bestLogit {
			best, bestLogit = oc, sum
		}
	}
	return byte(best)
}

// convPool evaluates a padded 3x3 convolution followed by ReLU and 2x2 max
// pooling. Four neighboring convolution sums share weights and source rows;
// explicit padding removes every per-pixel bounds branch from the kernel.
func convPool(src, dst []float32, size, channels int, weights, biases []float32) {
	stride := size + 2
	plane := stride * stride
	outSize := size / 2
	outStride := outSize + 2
	for oc, bias := range biases {
		for y := 0; y < outSize; y++ {
			for x := 0; x < outSize; x++ {
				a, b, c, d := bias, bias, bias, bias
				for ic := 0; ic < channels; ic++ {
					w := weights[(oc*channels+ic)*9 : (oc*channels+ic+1)*9]
					base := ic*plane + y*2*stride + x*2
					for ky := 0; ky < 3; ky++ {
						top := src[base+ky*stride : base+ky*stride+4]
						bottom := src[base+(ky+1)*stride : base+(ky+1)*stride+4]
						w0, w1, w2 := w[ky*3], w[ky*3+1], w[ky*3+2]
						a += top[0] * w0
						a += top[1] * w1
						a += top[2] * w2
						b += top[1] * w0
						b += top[2] * w1
						b += top[3] * w2
						c += bottom[0] * w0
						c += bottom[1] * w1
						c += bottom[2] * w2
						d += bottom[1] * w0
						d += bottom[2] * w1
						d += bottom[3] * w2
					}
				}
				if b > a {
					a = b
				}
				if c > a {
					a = c
				}
				if d > a {
					a = d
				}
				if a < 0 {
					a = 0
				}
				dst[oc*outStride*outStride+(y+1)*outStride+x+1] = a
			}
		}
	}
}
