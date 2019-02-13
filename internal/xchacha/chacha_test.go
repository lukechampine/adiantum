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
			msg := make([]byte, 4096)
			b.SetBytes(int64(len(msg)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				XORKeyStream(msg, msg, nonce, key, rounds)
			}
		}
	}

	b.Run("XChaCha8", withRounds(8))
	b.Run("XChaCha12", withRounds(12))
	b.Run("XChaCha20", withRounds(20))
}

func BenchmarkHChaCha(b *testing.B) {
	var key [32]byte
	rand.Read(key[:])
	var nonce [16]byte
	rand.Read(nonce[:])

	withRounds := func(rounds int) func(*testing.B) {
		return func(b *testing.B) {
			var out [32]byte
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				hChaCha(&out, &nonce, &key, rounds)
			}
		}
	}

	b.Run("HChaCha8", withRounds(8))
	b.Run("HChaCha12", withRounds(12))
	b.Run("HChaCha20", withRounds(20))
}
