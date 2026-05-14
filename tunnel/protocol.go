package tunnel

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"sync"
)

const (
	protoVersion = 1

	seqControl = uint8(0xFF)

	cmdPoll        = uint8(0x00)
	cmdVersion     = uint8(0x01)
	cmdFragSize    = uint8(0x02)
	cmdLazy        = uint8(0x03)
	cmdCompress    = uint8(0x04)
	cmdRecType     = uint8(0x05)
	cmdClose       = uint8(0x06)
	cmdOpenStream  = uint8(0x07)
	cmdCloseStream = uint8(0x08)

	flagLastFrag     = uint8(0x80)
	flagCompressed   = uint8(0x40)
	flagClosed       = uint8(0x20)
	flagStreamClosed = uint8(0x10)

	maxSeqNo          = 254
	downPktHeaderSize = 5
)

type UpMeta struct {
	Seq       uint8
	Frag      uint8
	LastFrag  bool
	Ack       uint8
	IsControl bool
	Command   uint8
	Param     uint8
}

func ParseMeta(s string) (UpMeta, error) {
	if len(s) != 6 {
		return UpMeta{}, fmt.Errorf("bad meta len %d", len(s))
	}
	ss, err := hexByte(s[0:2])
	if err != nil {
		return UpMeta{}, err
	}
	ff, err := hexByte(s[2:4])
	if err != nil {
		return UpMeta{}, err
	}
	aa, err := hexByte(s[4:6])
	if err != nil {
		return UpMeta{}, err
	}
	m := UpMeta{Seq: ss, Ack: aa}
	if ss == seqControl {
		m.IsControl = true
		m.Command = ff
		m.Param = aa
	} else {
		m.LastFrag = (ff & 0x80) != 0
		m.Frag = ff & 0x7F
	}
	return m, nil
}

func DataMeta(seq, frag, ack uint8, last bool) string {
	ff := frag & 0x7F
	if last {
		ff |= 0x80
	}
	return fmt.Sprintf("%02x%02x%02x", seq, ff, ack)
}

func CtrlMeta(cmd, param uint8) string {
	return fmt.Sprintf("ff%02x%02x", cmd, param)
}

type DownPkt struct {
	Seq          uint8
	Frag         uint8
	LastFrag     bool
	Ack          uint8
	StreamID     uint8
	Compressed   bool
	Closed       bool
	StreamClosed bool
	Payload      []byte
}

func (p *DownPkt) Encode() []byte {
	flags := uint8(0)
	if p.LastFrag {
		flags |= flagLastFrag
	}
	if p.Compressed {
		flags |= flagCompressed
	}
	if p.Closed {
		flags |= flagClosed
	}
	if p.StreamClosed {
		flags |= flagStreamClosed
	}
	fb := p.Frag & 0x7F
	if p.LastFrag {
		fb |= 0x80
	}
	out := make([]byte, 5+len(p.Payload))
	out[0] = flags
	out[1] = p.Seq
	out[2] = fb
	out[3] = p.Ack
	out[4] = p.StreamID
	copy(out[5:], p.Payload)
	return out
}

func DecodeDownPkt(data []byte) (*DownPkt, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("pkt too short: %d", len(data))
	}
	p := &DownPkt{
		Seq:          data[1],
		Ack:          data[3],
		StreamID:     data[4],
		Compressed:   (data[0] & flagCompressed) != 0,
		Closed:       (data[0] & flagClosed) != 0,
		StreamClosed: (data[0] & flagStreamClosed) != 0,
	}
	p.Frag = data[2] & 0x7F
	p.LastFrag = (data[2] & 0x80) != 0
	if len(data) > 5 {
		p.Payload = data[5:]
	}
	return p, nil
}

type FragBuf struct {
	mu    sync.Mutex
	frags map[uint8][]byte
	last  int
}

func NewFragBuf() *FragBuf {
	return &FragBuf{frags: make(map[uint8][]byte), last: -1}
}

func (fb *FragBuf) Add(idx uint8, isLast bool, data []byte) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	d := make([]byte, len(data))
	copy(d, data)
	fb.frags[idx] = d
	if isLast {
		fb.last = int(idx)
	}
}

func (fb *FragBuf) Complete() bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.last < 0 {
		return false
	}
	for i := 0; i <= fb.last; i++ {
		if _, ok := fb.frags[uint8(i)]; !ok {
			return false
		}
	}
	return true
}

func (fb *FragBuf) Assemble() []byte {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	var out []byte
	for i := 0; i <= fb.last; i++ {
		out = append(out, fb.frags[uint8(i)]...)
	}
	return out
}

func (fb *FragBuf) Reset() {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.frags = make(map[uint8][]byte)
	fb.last = -1
}

func ZlibCompress(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return data, false
	}
	w.Write(data)
	w.Close()
	if buf.Len() < len(data) {
		return buf.Bytes(), true
	}
	return data, false
}

func ZlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func hexByte(s string) (uint8, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("need 2 hex chars")
	}
	var v uint8
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint8(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint8(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint8(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex: %c", c)
		}
	}
	return v, nil
}

func nextSeq(s uint8) uint8 {
	s++
	if s > maxSeqNo {
		s = 0
	}
	return s
}
