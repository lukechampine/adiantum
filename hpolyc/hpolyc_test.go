package hpolyc

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestHPolyC_XChaCha20_32_AES256(t *testing.T) {
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
		block := make([]byte, 4096)
		tweak := make([]byte, 12)
		hpc := New(make([]byte, 32))
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			hpc.Encrypt(block, tweak)
		}
	})
	b.Run("Decrypt", func(b *testing.B) {
		block := make([]byte, 4096)
		tweak := make([]byte, 12)
		hpc := New(make([]byte, 32))
		b.SetBytes(int64(len(block)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			hpc.Decrypt(block, tweak)
		}
	})
}
