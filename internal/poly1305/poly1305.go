package poly1305

import "golang.org/x/crypto/poly1305"

// Hash implements hbsh.Hash with Poly1305.
type Hash struct {
	key [32]byte
}

// Sum implements hbsh.Hash.
func (h *Hash) Sum(dst, src []byte) []byte {
	var out [16]byte
	poly1305.Sum(&out, src, (*[32]byte)(&h.key))
	return append(dst, out[:]...)
}

// New returns a new Poly1305 instance using the specified key.
func New(key []byte) *Hash {
	if len(key) != 32 {
		panic("poly1305: invalid key length")
	}
	h := new(Hash)
	copy(h.key[:], key)
	return h
}
