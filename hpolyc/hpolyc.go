package hpolyc // import "lukechampine.com/adiantum/hpolyc"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/poly1305"
	"lukechampine.com/adiantum/hbsh"
	"lukechampine.com/adiantum/internal/xchacha"
)

type hpolycHash struct {
	key     [32]byte
	hashBuf []byte
}

func (h *hpolycHash) Sum(dst, msg, tweak []byte) []byte {
	needed := 4 + len(tweak) + len(msg)
	if headerSize := 4 + len(tweak); headerSize%16 != 0 {
		needed += 16 - (headerSize % 16)
	}
	if needed > cap(h.hashBuf) {
		h.hashBuf = make([]byte, needed)
	}
	h.hashBuf = h.hashBuf[:needed]
	binary.LittleEndian.PutUint32(h.hashBuf[:4], uint32(8*len(tweak)))
	copy(h.hashBuf[4:], tweak)
	copy(h.hashBuf[needed-len(msg):], msg)
	var out [16]byte
	poly1305.Sum(&out, h.hashBuf, &h.key)
	// clear secrets
	for i := range h.hashBuf {
		h.hashBuf[i] = 0
	}
	return append(dst, out[:]...)
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

func makeHPolyC(key []byte, chachaRounds int) (hbsh.StreamCipher, cipher.Block, hbsh.TweakableHash) {
	// create stream cipher and derive block+hash keys
	stream := &chachaStream{key, chachaRounds}
	keyBuf := make([]byte, 48)
	stream.XORKeyStream(keyBuf, nil)
	block, _ := aes.NewCipher(keyBuf[:32])
	hash := new(hpolycHash)
	copy(hash.key[:16], keyBuf[32:])
	return stream, block, hash
}

// New8 returns an HPolyC cipher with the specified key, using XChaCha8 as the
// stream cipher.
func New8(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 8))
}

// New returns an HPolyC cipher with the specified key.
func New(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 12))
}

// New20 returns an HPolyC cipher with the specified key, using XChaCha20 as the
// stream cipher.
func New20(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 20))
}
