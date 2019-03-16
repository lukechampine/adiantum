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
	key [32]byte
}

func (h *hpolycHash) Sum(dst, msg, tweak []byte) []byte {
	lenbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbuf, uint32(8*len(tweak)))
	padding := make([]byte, 16)[(4+len(tweak))%16:]
	mac := poly1305.New(&h.key)
	mac.Write(lenbuf)
	mac.Write(tweak)
	mac.Write(padding)
	mac.Write(msg)
	return mac.Sum(dst)
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
	if len(key) != xchacha.KeySize {
		panic("hpolyc: key must be 32 bytes long")
	}
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
// stream cipher. The key must be 32 bytes long.
func New8(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 8))
}

// New returns an HPolyC cipher with the specified key. The key must be 32 bytes
// long.
func New(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 12))
}

// New20 returns an HPolyC cipher with the specified key, using XChaCha20 as the
// stream cipher. The key must be 32 bytes long.
func New20(key []byte) *hbsh.HBSH {
	return hbsh.New(makeHPolyC(key, 20))
}
