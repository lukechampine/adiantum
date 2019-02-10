package poly1305

import (
	"crypto/rand"
	"testing"
)

func BenchmarkPoly1305(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	h := New(key)
	msg := make([]byte, 4096)
	out := make([]byte, 16)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Sum(out[:0], msg)
	}
}
