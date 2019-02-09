package hpolyc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func randBytes(n int) []byte {
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func randIntn(n int) int {
	r := binary.LittleEndian.Uint64(randBytes(8))
	r %= uint64(n)
	return int(r)
}

func TestHPolyC(t *testing.T) {
	for i := 0; i < 1000; i++ {
		block := randBytes(16 + randIntn(4096))
		tweak := randBytes(randIntn(16))
		hpc := New(randBytes(32))
		ciphertext := hpc.Encrypt(block, tweak)
		plaintext := hpc.Decrypt(ciphertext, tweak)
		if !bytes.Equal(plaintext, block) {
			t.Fatal("Decrypt is not the inverse of Encrypt")
		}
	}
}

func TestHPolyCEncryptionVectors(t *testing.T) {
	// Only 100 test vectors are included. To test the full set, replace this
	// file with the corresponding file from github.com/google/adiantum.
	js, err := ioutil.ReadFile("testdata/HPolyC_XChaCha20_32_AES256.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []struct {
		Description string `json:"description"`
		Input       struct {
			Key   string `json:"key_hex"`
			Tweak string `json:"tweak_hex"`
		} `json:"input"`
		Plaintext  string `json:"plaintext_hex"`
		Ciphertext string `json:"ciphertext_hex"`
	}
	if err := json.Unmarshal(js, &tests); err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		hpc := New(fromHex(test.Input.Key))
		ciphertext := hpc.Encrypt(fromHex(test.Plaintext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(ciphertext) != test.Ciphertext {
			t.Fatalf("%v (%v): Encryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Ciphertext, ciphertext)
		}
		plaintext := hpc.Decrypt(fromHex(test.Ciphertext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(plaintext) != test.Plaintext {
			t.Fatalf("%v (%v): Decryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Plaintext, plaintext)
		}
	}
}

func BenchmarkHPolyC(b *testing.B) {
	b.Run("Encrypt", func(b *testing.B) {
		block := randBytes(4096)
		tweak := randBytes(12)
		hpc := New(randBytes(32))
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			hpc.Encrypt(block, tweak)
		}
	})
	b.Run("Decrypt", func(b *testing.B) {
		block := randBytes(4096)
		tweak := randBytes(12)
		hpc := New(randBytes(32))
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			hpc.Decrypt(block, tweak)
		}
	})
}
