// +build !amd64

package nh

import "encoding/binary"

func sum(out *[32]byte, m []byte, key []byte) {
	var k [16]uint32
	for i := 4; i < 16; i++ {
		k[i] = binary.LittleEndian.Uint32(key[:4])
		key = key[4:]
	}

	var sums [4]uint64
	for len(m) > 0 {
		copy(k[:], k[4:])
		for i := 12; i < 16; i++ {
			k[i] = binary.LittleEndian.Uint32(key[:4])
			key = key[4:]
		}

		m0 := binary.LittleEndian.Uint32(m[0:4])
		m1 := binary.LittleEndian.Uint32(m[4:8])
		m2 := binary.LittleEndian.Uint32(m[8:12])
		m3 := binary.LittleEndian.Uint32(m[12:16])

		sums[0] += uint64(m0+k[0]) * uint64(m2+k[2])
		sums[1] += uint64(m0+k[4]) * uint64(m2+k[6])
		sums[2] += uint64(m0+k[8]) * uint64(m2+k[10])
		sums[3] += uint64(m0+k[12]) * uint64(m2+k[14])
		sums[0] += uint64(m1+k[1]) * uint64(m3+k[3])
		sums[1] += uint64(m1+k[5]) * uint64(m3+k[7])
		sums[2] += uint64(m1+k[9]) * uint64(m3+k[11])
		sums[3] += uint64(m1+k[13]) * uint64(m3+k[15])
		m = m[16:]
	}

	for i := range sums {
		binary.LittleEndian.PutUint64(out[i*8:], sums[i])
	}
}
