package hpolyc // import "lukechampine.com/adiantum/hpolyc"

import (
	"crypto/aes"
	"crypto/cipher"

	"lukechampine.com/adiantum/hbsh"
	"lukechampine.com/adiantum/internal/poly1305"
	"lukechampine.com/adiantum/internal/xchacha"
)

func makeHPolyC(key []byte, chachaRounds int) (hbsh.StreamCipher, cipher.Block, hbsh.Hash) {
	// create stream cipher and derive block+hash keys
	stream := xchacha.New(key, chachaRounds)
	keyBuf := make([]byte, 64)
	nonce := make([]byte, xchacha.NonceSize)
	nonce[0] = 1
	// we only want 16 bytes of entropy for poly1305, so leave the trailing 16
	// bytes zeroed
	stream.XORKeyStream(nonce, keyBuf[:48], keyBuf[:48])
	block, _ := aes.NewCipher(keyBuf[:32])
	hash := poly1305.New(keyBuf[32:64])
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
