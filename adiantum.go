package adiantum // import "lukechampine.com/adiantum"

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/poly1305"
	"lukechampine.com/adiantum/hbsh"
	"lukechampine.com/adiantum/internal/xchacha"
	"lukechampine.com/adiantum/nh"
)

// hashNHPoly1305 implements hbsh.Hash with NH and Poly1305.
type hashNHPoly1305 struct {
	keyT  [32]byte
	keyM  [32]byte
	keyNH [1072]byte
}

// Sum implements hbsh.Hash.
func (h *hashNHPoly1305) Sum(dst, msg, tweak []byte) []byte {
	// poly1305 hash append(bytes(8*len(msg)), tweak...) with keyT
	tweakBuf := make([]byte, 16+24)
	binary.LittleEndian.PutUint64(tweakBuf[:8], uint64(8*len(msg)))
	var outT [16]byte
	poly1305.Sum(&outT, append(tweakBuf[:16], tweak...), &h.keyT)

	// NH hash message in chunks of up to 1024 bytes
	var outNH [32]byte
	hashes := make([]byte, 0, 128) // won't need to realloc unless len(msg) > 4 KiB
	buf := bytes.NewBuffer(msg)
	for buf.Len() > 0 && buf.Len()%16 == 0 {
		nh.Sum(&outNH, buf.Next(1024), h.keyNH[:])
		hashes = append(hashes, outNH[:]...)
	}
	// if final chunk is not a multiple of 16 bytes, pad it
	if buf.Len() > 0 {
		var msgBuf [1024]byte
		n := copy(msgBuf[:], buf.Next(1024))
		if n%16 != 0 {
			n += 16 - (n % 16)
		}
		nh.Sum(&outNH, msgBuf[:n], h.keyNH[:])
		hashes = append(hashes, outNH[:]...)
	}

	// poly1305 hash the NH hashes with keyM
	var outM [16]byte
	poly1305.Sum(&outM, hashes, &h.keyM)

	// return the sum of the hashes
	sum := addHashes(outT, outM)
	return append(dst[:0], sum[:]...)
}

type chachaStream struct {
	key    []byte
	rounds int
}

func (s *chachaStream) XORKeyStream(msg, nonce []byte) {
	nonceBuf := make([]byte, 24)
	n := copy(nonceBuf, nonce)
	nonceBuf[n] = 1
	xchacha.XORKeyStream(msg, msg, nonceBuf, s.key, s.rounds)
}

func makeAdiantum(key []byte, chachaRounds int) (hbsh.StreamCipher, cipher.Block, hbsh.TweakableHash) {
	// create stream cipher and derive block+hash keys
	stream := &chachaStream{key, chachaRounds}
	keyBuf := bytes.NewBuffer(make([]byte, 32+16+16+1072))
	stream.XORKeyStream(keyBuf.Bytes(), nil)
	block, _ := aes.NewCipher(keyBuf.Next(32))
	hash := new(hashNHPoly1305)
	copy(hash.keyT[:16], keyBuf.Next(16))
	copy(hash.keyM[:16], keyBuf.Next(16))
	copy(hash.keyNH[:], keyBuf.Next(1072))
	return stream, block, hash
}

// New8 returns an Adiantum cipher with the specified key, using XChaCha8 as the
// stream cipher.
func New8(key []byte) *hbsh.HBSH {
	return hbsh.New(makeAdiantum(key, 8))
}

// New returns an Adiantum cipher with the specified key.
func New(key []byte) *hbsh.HBSH {
	return hbsh.New(makeAdiantum(key, 12))
}

// New20 returns an Adiantum cipher with the specified key, using XChaCha20 as
// the stream cipher.
func New20(key []byte) *hbsh.HBSH {
	return hbsh.New(makeAdiantum(key, 20))
}

func addHashes(x, y [16]byte) [16]byte {
	x1 := binary.LittleEndian.Uint64(x[:8])
	x2 := binary.LittleEndian.Uint64(x[8:16])
	y1 := binary.LittleEndian.Uint64(y[:8])
	y2 := binary.LittleEndian.Uint64(y[8:16])
	r1 := x1 + y1
	r2 := x2 + y2
	if r1 < x1 {
		r2++
	}
	binary.LittleEndian.PutUint64(x[:8], r1)
	binary.LittleEndian.PutUint64(x[8:], r2)
	return x
}
