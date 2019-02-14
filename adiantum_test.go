package adiantum

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"lukechampine.com/adiantum/hbsh"
)

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

type testVector struct {
	Description string `json:"description"`
	Input       struct {
		Key   string `json:"key_hex"`
		Tweak string `json:"tweak_hex"`
	} `json:"input"`
	Plaintext  string `json:"plaintext_hex"`
	Ciphertext string `json:"ciphertext_hex"`
}

func readTestVectors(t *testing.T, filename string) []testVector {
	t.Helper()
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var tests []testVector
	if err := json.Unmarshal(js, &tests); err != nil {
		t.Fatal(err)
	}
	return tests
}

func TestAdiantum_XChaCha8_32_AES256(t *testing.T) {
	tests := readTestVectors(t, "testdata/Adiantum_XChaCha8_32_AES256.json")
	for i, test := range tests {
		c := New8(fromHex(test.Input.Key))
		ciphertext := c.Encrypt(fromHex(test.Plaintext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(ciphertext) != test.Ciphertext {
			t.Fatalf("%v (%v): Encryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Ciphertext, ciphertext)
		}
		plaintext := c.Decrypt(fromHex(test.Ciphertext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(plaintext) != test.Plaintext {
			t.Fatalf("%v (%v): Decryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Plaintext, plaintext)
		}
	}
}

func TestAdiantum_XChaCha12_32_AES256(t *testing.T) {
	tests := readTestVectors(t, "testdata/Adiantum_XChaCha12_32_AES256.json")
	for i, test := range tests {
		c := New(fromHex(test.Input.Key))
		ciphertext := c.Encrypt(fromHex(test.Plaintext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(ciphertext) != test.Ciphertext {
			t.Fatalf("%v (%v): Encryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Ciphertext, ciphertext)
		}
		plaintext := c.Decrypt(fromHex(test.Ciphertext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(plaintext) != test.Plaintext {
			t.Fatalf("%v (%v): Decryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Plaintext, plaintext)
		}
	}
}

func TestAdiantum_XChaCha20_32_AES256(t *testing.T) {
	tests := readTestVectors(t, "testdata/Adiantum_XChaCha20_32_AES256.json")
	for i, test := range tests {
		c := New20(fromHex(test.Input.Key))
		ciphertext := c.Encrypt(fromHex(test.Plaintext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(ciphertext) != test.Ciphertext {
			t.Fatalf("%v (%v): Encryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Ciphertext, ciphertext)
		}
		plaintext := c.Decrypt(fromHex(test.Ciphertext), fromHex(test.Input.Tweak))
		if hex.EncodeToString(plaintext) != test.Plaintext {
			t.Fatalf("%v (%v): Decryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Plaintext, plaintext)
		}
	}
}

func BenchmarkAdiantum(b *testing.B) {
	runEncrypt := func(c *hbsh.HBSH) func(*testing.B) {
		return func(b *testing.B) {
			block := make([]byte, 4096)
			tweak := make([]byte, 12)
			b.SetBytes(int64(len(block)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.Encrypt(block, tweak)
			}
		}
	}
	runDecrypt := func(c *hbsh.HBSH) func(*testing.B) {
		return func(b *testing.B) {
			block := make([]byte, 4096)
			tweak := make([]byte, 12)
			b.SetBytes(int64(len(block)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.Decrypt(block, tweak)
			}
		}
	}

	b.Run("XChaCha8_Encrypt", runEncrypt(New8(make([]byte, 32))))
	b.Run("XChaCha8_Decrypt", runDecrypt(New8(make([]byte, 32))))
	b.Run("XChaCha12_Encrypt", runEncrypt(New(make([]byte, 32))))
	b.Run("XChaCha12_Decrypt", runDecrypt(New(make([]byte, 32))))
	b.Run("XChaCha20_Encrypt", runEncrypt(New20(make([]byte, 32))))
	b.Run("XChaCha20_Decrypt", runDecrypt(New20(make([]byte, 32))))
}
