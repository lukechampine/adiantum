package hpolyc // import "lukechampine.com/adiantum/hpolyc"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/poly1305"
)

// HPolyC is an HBSH cipher, using XChaCha20, Poly1305, and AES.
type HPolyC struct {
	streamKey []byte
	block     cipher.Block
	polyKey   [32]byte

	hashBuf []byte
	sumBuf  [16]byte
}

func (h *HPolyC) streamXOR(nonce, msg []byte) []byte {
	var nonceBuf [chacha.XNonceSize]byte
	n := copy(nonceBuf[:], nonce)
	nonceBuf[n] = 1
	chacha.XORKeyStream(msg, msg, nonceBuf[:], h.streamKey, 20)
	return msg
}

func (h *HPolyC) encryptBlock(src []byte) []byte {
	h.block.Encrypt(src, src)
	return src
}

func (h *HPolyC) decryptBlock(src []byte) []byte {
	h.block.Decrypt(src, src)
	return src
}

func (h *HPolyC) hash(tweak, msg []byte) []byte {
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
	poly1305.Sum(&h.sumBuf, h.hashBuf, &h.polyKey)
	// wipe secrets
	for i := range h.hashBuf {
		h.hashBuf[i] = 0
	}
	return h.sumBuf[:]
}

// Encrypt encrypts block using the specified tweak.
func (h *HPolyC) Encrypt(block, tweak []byte) []byte {
	pl, pr := block[:len(block)-16], block[len(block)-16:]
	pm := blockAdd(pr, h.hash(tweak, pl))
	cm := h.encryptBlock(pm)
	cl := h.streamXOR(cm, pl)
	cr := blockSub(cm, h.hash(tweak, cl))
	return append(cl, cr...) // reuses block's memory
}

// Decrypt decrypts block using the specified tweak.
func (h *HPolyC) Decrypt(block, tweak []byte) []byte {
	cl, cr := block[:len(block)-16], block[len(block)-16:]
	cm := blockAdd(cr, h.hash(tweak, cl))
	pl := h.streamXOR(cm, cl)
	pm := h.decryptBlock(cm)
	pr := blockSub(pm, h.hash(tweak, pl))
	return append(pl, pr...) // reuses block's memory
}

// New returns an HPolyC cipher with the specified key.
func New(key []byte) *HPolyC {
	h := &HPolyC{
		streamKey: append([]byte(nil), key...),
	}
	keyBuf := make([]byte, 32+16)
	keyBuf = h.streamXOR(nil, keyBuf)
	h.block, _ = aes.NewCipher(keyBuf[:32])
	copy(h.polyKey[:16], keyBuf[32:])
	return h
}

func add64(x, y, carry uint64) (sum, carryOut uint64) {
	yc := y + carry
	sum = x + yc
	if sum < x || yc < y {
		carryOut = 1
	}
	return
}

func sub64(x, y, borrow uint64) (diff, borrowOut uint64) {
	yb := y + borrow
	diff = x - yb
	if diff > x || yb < y {
		borrowOut = 1
	}
	return
}

func blockAdd(x []byte, y []byte) []byte {
	x1 := binary.LittleEndian.Uint64(x[:8])
	x2 := binary.LittleEndian.Uint64(x[8:16])
	y1 := binary.LittleEndian.Uint64(y[:8])
	y2 := binary.LittleEndian.Uint64(y[8:16])

	r1, c := add64(x1, y1, 0)
	r2, _ := add64(x2, y2, c)

	binary.LittleEndian.PutUint64(x[:8], r1)
	binary.LittleEndian.PutUint64(x[8:], r2)
	return x
}

func blockSub(x []byte, y []byte) []byte {
	x1 := binary.LittleEndian.Uint64(x[:8])
	x2 := binary.LittleEndian.Uint64(x[8:16])
	y1 := binary.LittleEndian.Uint64(y[:8])
	y2 := binary.LittleEndian.Uint64(y[8:16])

	r1, c := sub64(x1, y1, 0)
	r2, _ := sub64(x2, y2, c)

	binary.LittleEndian.PutUint64(x[:8], r1)
	binary.LittleEndian.PutUint64(x[8:], r2)
	return x
}
