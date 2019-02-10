package xchacha

import (
	"crypto/rand"
	"testing"
)

func BenchmarkXChaCha(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	withRounds := func(rounds int) func(*testing.B) {
		return func(b *testing.B) {
			c := New(key, rounds)
			msg := make([]byte, 4096)
			b.SetBytes(int64(len(msg)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.XORKeyStream(nonce, msg, msg)
			}
		}
	}

	b.Run("XChaCha8", withRounds(8))
	b.Run("XChaCha12", withRounds(12))
	b.Run("XChaCha20", withRounds(20))
}
