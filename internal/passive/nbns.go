package passive

import (
	"encoding/binary"
	"strings"
)

// NetBIOS name service opcodes (bits 11–14 of the flags word).
const (
	nbnsOpRegistration = 5
	nbnsOpRefresh      = 8
	nbnsOpRefreshAlt   = 9

	nbSuffixWorkstation = 0x00
)

// nbnsRegistration returns the workstation name a Windows (or Samba)
// machine broadcasts when it registers itself, or "".
func nbnsRegistration(msg []byte) string {
	if len(msg) < 12+34 || msg[2]&0x80 != 0 { // requests only
		return ""
	}
	switch (binary.BigEndian.Uint16(msg[2:4]) >> 11) & 0x0f {
	case nbnsOpRegistration, nbnsOpRefresh, nbnsOpRefreshAlt:
	default:
		return ""
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return ""
	}
	name, suffix, ok := DecodeNetBIOSName(msg[12:])
	if !ok || suffix != nbSuffixWorkstation {
		return ""
	}
	return name
}

// DecodeNetBIOSName decodes the 32-byte "first level" encoded name that
// follows its length byte (0x20) at the start of b.
func DecodeNetBIOSName(b []byte) (name string, suffix byte, ok bool) {
	if len(b) < 34 || b[0] != 0x20 {
		return "", 0, false
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, lo := b[1+2*i]-'A', b[2+2*i]-'A'
		if hi > 15 || lo > 15 {
			return "", 0, false
		}
		raw[i] = hi<<4 | lo
	}
	return CleanNetBIOS(raw[:15]), raw[15], true
}

// CleanNetBIOS trims a raw 15-byte NetBIOS name.
func CleanNetBIOS(raw []byte) string {
	return cleanName(strings.TrimRight(string(raw), " \x00"))
}
