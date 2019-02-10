package hpolyc // import "lukechampine.com/adiantum/hpolyc"

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/poly1305"
	"lukechampine.com/adiantum/hbsh"
)

// xchachaStream implements hbsh.StreamCipher with XChaCha.
type xchachaStream struct {
	key    []byte
	rounds int
}

// XORKeyStream implements hbsh.StreamCipher.
func (c *xchachaStream) XORKeyStream(nonce, dst, src []byte) {
	// expand nonce with HChaCha
	var tmpKey [32]byte
	var hNonce [16]byte
	copy(hNonce[:], nonce[:16])
	copy(tmpKey[:], c.key)
	hChaCha(&tmpKey, &hNonce, &tmpKey, c.rounds)
	chacha.XORKeyStream(dst, src, nonce[16:], tmpKey[:], c.rounds)
}

// NonceSize implements hbsh.StreamCipher.
func (xchachaStream) NonceSize() int { return chacha.XNonceSize }

// hashPoly1305 implements hbsh.Hash with poly1305.
type hashPoly1305 [32]byte

// Sum implements hbsh.Hash.
func (key hashPoly1305) Sum(dst, src []byte) []byte {
	var out [16]byte
	poly1305.Sum(&out, src, (*[32]byte)(&key))
	return append(dst, out[:]...)
}

func makeHPolyC(key []byte, chachaRounds int) (hbsh.StreamCipher, cipher.Block, hbsh.Hash) {
	// create stream cipher and derive block+hash keys
	stream := &xchachaStream{key, chachaRounds}
	keyBuf := make([]byte, 32+16)
	nonce := make([]byte, chacha.XNonceSize)
	nonce[0] = 1
	stream.XORKeyStream(nonce, keyBuf, keyBuf)
	block, _ := aes.NewCipher(keyBuf[:32])
	var hash hashPoly1305
	copy(hash[:16], keyBuf[32:])
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
