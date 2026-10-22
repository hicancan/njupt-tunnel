package tunnel

import (
	"encoding/binary"
	"io"
)

const (
	txHeaderSize  = 12
	rxHeaderSize  = 8 // The gateway omits the stream ID after authentication.
	maxFrameSize  = 65535
	typeAuth      = 1
	typeAuthReply = 2
	typeHeartbeat = 3
	typeIPv4      = 4

	// Handshake attribute tags the gateway sends. Observed tags we deliberately
	// ignore: 0x23 (tunnel peer), 0x24 (a loopback DNS address, never the
	// campus resolver), 0x2b, 0x35 and 0x36 (IPv6, which is never assigned).
	attrAddress = 0x0b
	attrNetmask = 0x0c
	attrEnd     = 0xff
)

func encodeHeader(dst []byte, kind byte, size int) {
	copy(dst[:txHeaderSize], []byte{1, kind, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0})
	binary.BigEndian.PutUint16(dst[2:4], uint16(size))
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
