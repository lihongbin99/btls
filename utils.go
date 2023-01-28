package btls

import "math/rand"

func toUint8(buf []byte) uint8 {
	return uint8(buf[0])
}

func toUint16(buf []byte) uint16 {
	return (uint16(buf[0]) << 8) | uint16(buf[1])
}

func Uint16toBuf(n uint16) []byte {
	return []byte{byte(n >> 8), byte(n & 0xFF)}
}

type uint24 uint32

func toUint24(buf []byte) uint24 {
	return (uint24(buf[0]) << 16) | (uint24(buf[1]) << 8) | uint24(buf[2])
}

func Uint24toBuf(n uint24) []byte {
	return []byte{byte(n >> 16), byte(n >> 8 & 0xFF), byte(n & 0xFF)}
}

func MakeRandomBuf(n int) []byte {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(rand.Intn(0x100))
	}
	return buf
}
