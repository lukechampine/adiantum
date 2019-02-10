package hpolyc // import "lukechampine.com/adiantum/hpolyc"

import (
	"crypto/aes"

	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/poly1305"
	"lukechampine.com/adiantum/hbsh"
)

// xchacha12Stream implements hbsh.StreamCipher with XChaCha12.
type xchacha12Stream []byte

// XORKeyStream implements hbsh.StreamCipher.
func (key xchacha12Stream) XORKeyStream(nonce, dst, src []byte) {
	// expand nonce with HChaCha12
	var tmpKey [32]byte
	var hNonce [16]byte
	copy(hNonce[:], nonce[:16])
	copy(tmpKey[:], key)
	hChaCha12(&tmpKey, &hNonce, &tmpKey)
	chacha.XORKeyStream(dst, src, nonce[16:], tmpKey[:], 12)
}

// NonceSize implements hbsh.StreamCipher.
func (xchacha12Stream) NonceSize() int { return chacha.XNonceSize }

// xchacha20Stream implements hbsh.StreamCipher with XChaCha20.
type xchacha20Stream []byte

// XORKeyStream implements hbsh.StreamCipher.
func (key xchacha20Stream) XORKeyStream(nonce, dst, src []byte) {
	chacha.XORKeyStream(dst, src, nonce, []byte(key), 20)
}

// NonceSize implements hbsh.StreamCipher.
func (xchacha20Stream) NonceSize() int { return chacha.XNonceSize }

// hashPoly1305 implements hbsh.Hash with poly1305.
type hashPoly1305 [32]byte

// Sum implements hbsh.Hash.
func (key hashPoly1305) Sum(dst, src []byte) []byte {
	var out [16]byte
	poly1305.Sum(&out, src, (*[32]byte)(&key))
	return append(dst, out[:]...)
}

// New returns an HPolyC cipher with the specified key.
func New(key []byte) *hbsh.HBSH {
	// create stream cipher and derive block+hash keys
	stream := xchacha12Stream(key)
	keyBuf := make([]byte, 32+16)
	nonce := make([]byte, chacha.XNonceSize)
	nonce[0] = 1
	stream.XORKeyStream(nonce, keyBuf, keyBuf)
	block, _ := aes.NewCipher(keyBuf[:32])
	var hash hashPoly1305
	copy(hash[:16], keyBuf[32:])
	return hbsh.New(stream, block, hash)
}

// New20 returns an HPolyC cipher with the specified key, using XChaCha20 as the
// stream cipher.
func New20(key []byte) *hbsh.HBSH {
	stream := xchacha20Stream(key)
	keyBuf := make([]byte, 32+16)
	nonce := make([]byte, chacha.XNonceSize)
	nonce[0] = 1
	stream.XORKeyStream(nonce, keyBuf, keyBuf)
	block, _ := aes.NewCipher(keyBuf[:32])
	var hash hashPoly1305
	copy(hash[:16], keyBuf[32:])
	return hbsh.New(stream, block, hash)
}
