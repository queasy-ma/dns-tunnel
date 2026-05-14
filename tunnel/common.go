package tunnel

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	maxDNSNameLen = 250
	maxLabelSize  = 63
	maxRetries    = 10
	retryDelay    = 1 * time.Second
	dnsTimeout    = 5 * time.Second
	lazyTimeout   = 1 * time.Second
	// minLazyHold is the floor that handlePollWithAck enforces even when
	// session.lazyMode is somehow false. Caps tight-loop poll frequency at
	// ~10/s on the server side regardless of client behavior. Small enough
	// not to affect normal latency (much less than typical RTT budgets).
	minLazyHold = 100 * time.Millisecond
	pollDelay   = 50 * time.Millisecond

	sessionIDLength = 7
	cmcLength       = 4
	defaultTLD      = "edu"
	metaLength      = 6

	maxDownPayloadTXT  = 200
	maxDownPayloadNULL = 500

	DefaultKey = "!QAZ@WSX#EDC$RFV%TGB^YHN"

	EncBase32 = 0
	EncBase64 = 1

	maxStreams = 254
)

var (
	dnsBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	dnsBase64 = base64.URLEncoding.WithPadding(base64.NoPadding)
)

func generateCMC() string {
	b := make([]byte, cmcLength/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func encodeDNSSafe(data []byte, enc int) string {
	if len(data) == 0 {
		return "AA"
	}
	var encoded string
	switch enc {
	case EncBase64:
		encoded = dnsBase64.EncodeToString(data)
	default:
		encoded = dnsBase32.EncodeToString(data)
	}
	var labels []string
	for i := 0; i < len(encoded); i += maxLabelSize {
		end := i + maxLabelSize
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	return strings.Join(labels, ".")
}

func decodeDNSSafe(s string, enc int) ([]byte, error) {
	s = strings.ReplaceAll(s, ".", "")
	if s == "" || s == "AA" {
		return []byte{}, nil
	}
	switch enc {
	case EncBase64:
		return dnsBase64.DecodeString(s)
	default:
		return dnsBase32.DecodeString(strings.ToUpper(s))
	}
}

func generateSessionID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	result := make([]byte, sessionIDLength)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

func maxUpPayload(tld string, enc int) int {
	overhead := cmcLength + 1 + metaLength + 1 + sessionIDLength + 1 + len(tld) + 1 + 2
	avail := maxDNSNameLen - overhead
	if avail < 0 {
		return 0
	}
	dataChars := avail - avail/maxLabelSize
	switch enc {
	case EncBase64:
		return dataChars * 3 / 4
	default:
		return dataChars * 5 / 8
	}
}

func vigenereEncrypt(data []byte, key string) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = byte((int(b) + int(key[i%len(key)])) % 256)
	}
	return result
}

func vigenereDecrypt(data []byte, key string) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = byte((int(b) - int(key[i%len(key)]) + 256) % 256)
	}
	return result
}

type DataBuf struct {
	mu   sync.Mutex
	data []byte
}

func (b *DataBuf) Write(d []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, d...)
}

func (b *DataBuf) Take(max int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data) == 0 {
		return nil
	}
	n := max
	if n > len(b.data) {
		n = len(b.data)
	}
	chunk := make([]byte, n)
	copy(chunk, b.data[:n])
	b.data = b.data[n:]
	return chunk
}

func (b *DataBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

func testEncodingRoundtrip(data []byte, enc int) bool {
	encoded := encodeDNSSafe(data, enc)
	decoded, err := decodeDNSSafe(encoded, enc)
	if err != nil {
		return false
	}
	if len(decoded) != len(data) {
		return false
	}
	for i := range data {
		if data[i] != decoded[i] {
			return false
		}
	}
	return true
}

func generateFragSizeProbe(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	return data
}

func buildFQDN(parts ...string) string {
	return strings.Join(parts, ".")
}

func formatSize(size int) string {
	return fmt.Sprintf("%04x", size)
}

func parseSize(s string) (int, error) {
	if len(s) != 4 {
		return 0, fmt.Errorf("bad size: %s", s)
	}
	var v int
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= int(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex: %c", c)
		}
	}
	return v, nil
}
