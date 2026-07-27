// Package ja4 implements TLS ClientHello parsing and JA4 fingerprint
// computation per the FoxIO JA4 specification:
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
// JA4 = JA4_a + "_" + JA4_b + "_" + JA4_c
//
//	JA4_a: protocol, TLS version, SNI presence, cipher count, extension
//	       count, first ALPN value's first+last characters
//	JA4_b: sha256[:12] of the sorted cipher suite list
//	JA4_c: sha256[:12] of the sorted extension list (minus SNI and ALPN)
//	       plus the signature algorithms in offered order
//
// GREASE values (RFC 8701) are excluded everywhere.
package ja4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	extServerName        = 0x0000
	extSignatureAlgs     = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b

	maxHandshakeLen = 1 << 17 // 128 KiB sanity cap on ClientHello size
	maxRecordLen    = 16384 + 256
)

var (
	ErrNotTLSHandshake = errors.New("ja4: not a TLS handshake record")
	ErrNotClientHello  = errors.New("ja4: handshake message is not a ClientHello")
	ErrMalformed       = errors.New("ja4: malformed ClientHello")
)

// ClientHello holds the fields of a parsed TLS ClientHello that JA4 needs.
type ClientHello struct {
	LegacyVersion     uint16
	CipherSuites      []uint16 // offered order, GREASE included
	Extensions        []uint16 // offered order, GREASE included
	SupportedVersions []uint16 // from the supported_versions extension
	SigAlgs           []uint16 // from signature_algorithms, offered order
	ALPN              []string // offered protocol list
	SNI               string   // server_name host, "" if absent
	HasSNI            bool
}

// isGREASE reports whether v is a GREASE value per RFC 8701 (0x0a0a,
// 0x1a1a, ..., 0xfafa: both bytes equal with low nibble 0xa).
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

// ReadClientHello reads TLS records from r until a complete ClientHello
// handshake message is assembled, then parses it. It returns the parsed
// hello and every byte consumed from r, so the caller can replay them into
// a real TLS stack afterwards. The consumed bytes are returned even on
// error.
func ReadClientHello(r io.Reader) (*ClientHello, []byte, error) {
	consumed := &bytes.Buffer{}
	tr := io.TeeReader(r, consumed)

	msg, err := readHandshakeMessage(tr)
	if err != nil {
		return nil, consumed.Bytes(), err
	}
	ch, err := parseClientHelloBody(msg)
	return ch, consumed.Bytes(), err
}

// readHandshakeMessage assembles one handshake message body (header
// stripped) from one or more TLS records, verifying it is a ClientHello.
func readHandshakeMessage(r io.Reader) ([]byte, error) {
	payload, err := readRecord(r)
	if err != nil {
		return nil, err
	}
	// Handshake header: msg_type(1) + length(3).
	for len(payload) < 4 {
		next, err := readRecord(r)
		if err != nil {
			return nil, err
		}
		payload = append(payload, next...)
	}
	if payload[0] != 0x01 {
		return nil, ErrNotClientHello
	}
	msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if msgLen > maxHandshakeLen {
		return nil, ErrMalformed
	}
	for len(payload)-4 < msgLen {
		next, err := readRecord(r)
		if err != nil {
			return nil, err
		}
		payload = append(payload, next...)
	}
	return payload[4 : 4+msgLen], nil
}

// readRecord reads a single TLS record and returns its payload, verifying
// the record type is handshake (0x16).
func readRecord(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("ja4: reading record header: %w", err)
	}
	if hdr[0] != 0x16 {
		return nil, ErrNotTLSHandshake
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 || n > maxRecordLen {
		return nil, ErrMalformed
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("ja4: reading record payload: %w", err)
	}
	return payload, nil
}

// cursor is a bounds-checked reader over the ClientHello body.
type cursor struct {
	b   []byte
	off int
	err bool
}

func (c *cursor) take(n int) []byte {
	if c.err || c.off+n > len(c.b) {
		c.err = true
		return nil
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v
}

func (c *cursor) u8() int {
	b := c.take(1)
	if c.err {
		return 0
	}
	return int(b[0])
}
func (c *cursor) u16() int {
	b := c.take(2)
	if c.err {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func parseClientHelloBody(body []byte) (*ClientHello, error) {
	c := &cursor{b: body}
	ch := &ClientHello{}

	ch.LegacyVersion = uint16(c.u16())
	c.take(32)     // random
	c.take(c.u8()) // legacy_session_id

	cipherBytes := c.take(c.u16())
	if c.err || len(cipherBytes)%2 != 0 {
		return nil, ErrMalformed
	}
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(cipherBytes[i:]))
	}

	c.take(c.u8()) // legacy_compression_methods

	if c.err {
		return nil, ErrMalformed
	}
	if c.off == len(c.b) {
		return ch, nil // no extensions (ancient client) — still valid
	}

	extBytes := c.take(c.u16())
	if c.err {
		return nil, ErrMalformed
	}
	ec := &cursor{b: extBytes}
	for ec.off < len(ec.b) {
		extType := uint16(ec.u16())
		data := ec.take(ec.u16())
		if ec.err {
			return nil, ErrMalformed
		}
		ch.Extensions = append(ch.Extensions, extType)
		parseExtension(ch, extType, data)
	}
	return ch, nil
}

func parseExtension(ch *ClientHello, extType uint16, data []byte) {
	d := &cursor{b: data}
	switch extType {
	case extServerName:
		ch.HasSNI = true
		d.u16()          // server_name_list length
		if d.u8() == 0 { // name_type == host_name
			name := d.take(d.u16())
			if !d.err {
				ch.SNI = string(name)
			}
		}
	case extALPN:
		d.u16() // protocol_name_list length
		for !d.err && d.off < len(d.b) {
			p := d.take(d.u8())
			if !d.err {
				ch.ALPN = append(ch.ALPN, string(p))
			}
		}
	case extSignatureAlgs:
		sigBytes := d.take(d.u16())
		for i := 0; !d.err && i+1 < len(sigBytes); i += 2 {
			ch.SigAlgs = append(ch.SigAlgs, binary.BigEndian.Uint16(sigBytes[i:]))
		}
	case extSupportedVersions:
		verBytes := d.take(d.u8())
		for i := 0; !d.err && i+1 < len(verBytes); i += 2 {
			ch.SupportedVersions = append(ch.SupportedVersions, binary.BigEndian.Uint16(verBytes[i:]))
		}
	}
}

// JA4 computes the JA4 fingerprint string for the parsed ClientHello.
func (ch *ClientHello) JA4() string {
	return ch.ja4a() + "_" + ch.ja4b() + "_" + ch.ja4c()
}

func (ch *ClientHello) ja4a() string {
	sni := "i"
	if ch.HasSNI {
		sni = "d"
	}
	nCiphers := len(filterGREASE(ch.CipherSuites))
	nExts := len(filterGREASE(ch.Extensions))
	return fmt.Sprintf("t%s%s%02d%02d%s",
		versionString(ch.effectiveVersion()), sni,
		min(nCiphers, 99), min(nExts, 99), alpnChars(ch.ALPN))
}

func (ch *ClientHello) ja4b() string {
	ciphers := filterGREASE(ch.CipherSuites)
	if len(ciphers) == 0 {
		return "000000000000"
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	return hash12(joinHex(ciphers))
}

func (ch *ClientHello) ja4c() string {
	var exts []uint16
	for _, e := range filterGREASE(ch.Extensions) {
		// SNI and ALPN are counted in JA4_a but excluded from the hash:
		// they vary per destination, not per client stack.
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return "000000000000"
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	input := joinHex(exts)
	if sigs := filterGREASE(ch.SigAlgs); len(sigs) > 0 {
		input += "_" + joinHex(sigs) // offered order, NOT sorted, per spec
	}
	return hash12(input)
}

// effectiveVersion is the highest non-GREASE version in supported_versions
// if present, otherwise the legacy record version.
func (ch *ClientHello) effectiveVersion() uint16 {
	best := uint16(0)
	for _, v := range ch.SupportedVersions {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	return ch.LegacyVersion
}

func versionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

// alpnChars returns the first and last character of the first offered ALPN
// value, or "00" if no ALPN. Non-alphanumeric endpoints fall back to the
// first hex digit of the first byte and last hex digit of the last byte.
func alpnChars(alpn []string) string {
	if len(alpn) == 0 || len(alpn[0]) == 0 {
		return "00"
	}
	s := alpn[0]
	first, last := s[0], s[len(s)-1]
	if isAlnum(first) && isAlnum(last) {
		return string(first) + string(last)
	}
	fh := fmt.Sprintf("%02x", first)
	lh := fmt.Sprintf("%02x", last)
	return fh[:1] + lh[1:]
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinHex(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}
