package hbsh

import (
	"crypto/cipher"
	"encoding/binary"
)

// A StreamCipher xors bytes with a keystream.
type StreamCipher interface {
	XORKeyStream(nonce, dst, src []byte)
	NonceSize() int
}

// Hash is a cryptographic hash function. It appends the hash of src to dst and
// returns it.
type Hash interface {
	Sum(dst, src []byte) []byte
}

// HBSH is a cipher using the HBSH encryption mode.
type HBSH struct {
	stream StreamCipher
	block  cipher.Block
	hash   Hash

	nonceBuf []byte
	hashBuf  []byte
	sumBuf   []byte
}

func (h *HBSH) tweakedHash(tweak, msg []byte) []byte {
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
	h.sumBuf = h.hash.Sum(h.sumBuf[:0], h.hashBuf)
	return h.sumBuf
}

func (h *HBSH) streamXOR(nonce, msg []byte) []byte {
	for i := range h.nonceBuf {
		h.nonceBuf[i] = 0
	}
	n := copy(h.nonceBuf, nonce)
	h.nonceBuf[n] = 1
	h.stream.XORKeyStream(h.nonceBuf, msg, msg)
	return msg
}

func (h *HBSH) encryptBlock(src []byte) []byte {
	h.block.Encrypt(src, src)
	return src
}

func (h *HBSH) decryptBlock(src []byte) []byte {
	h.block.Decrypt(src, src)
	return src
}

// Encrypt encrypts block using the specified tweak.
func (h *HBSH) Encrypt(block, tweak []byte) []byte {
	pl, pr := block[:len(block)-16], block[len(block)-16:]
	pm := blockAdd(pr, h.tweakedHash(tweak, pl))
	cm := h.encryptBlock(pm)
	cl := h.streamXOR(cm, pl)
	cr := blockSub(cm, h.tweakedHash(tweak, cl))
	return append(cl, cr...)
}

// Decrypt decrypts block using the specified tweak.
func (h *HBSH) Decrypt(block, tweak []byte) []byte {
	cl, cr := block[:len(block)-16], block[len(block)-16:]
	cm := blockAdd(cr, h.tweakedHash(tweak, cl))
	pl := h.streamXOR(cm, cl)
	pm := h.decryptBlock(cm)
	pr := blockSub(pm, h.tweakedHash(tweak, pl))
	return append(pl, pr...)
}

// New returns an HBSH cipher using the specified primitives.
func New(stream StreamCipher, block cipher.Block, hash Hash) *HBSH {
	return &HBSH{
		stream:   stream,
		block:    block,
		hash:     hash,
		nonceBuf: make([]byte, stream.NonceSize()),
	}
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
