package nh

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

type testVector struct {
	Description string `json:"description"`
	Input       struct {
		Key     string `json:"key_hex"`
		Message string `json:"message_hex"`
	} `json:"input"`
	Hash string `json:"hash_hex"`
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

func TestNH(t *testing.T) {
	// Only 20 test vectors are included. To test the full set, replace this
	// file with the corresponding file from github.com/google/adiantum.
	tests := readTestVectors(t, "testdata/NH.json")
	for i, test := range tests {
		var out [32]byte
		Sum(&out, fromHex(test.Input.Message), fromHex(test.Input.Key))
		if hex.EncodeToString(out[:]) != test.Hash {
			t.Fatalf("%v (%v): Encryption failed:\nexp: %v\ngot: %x", test.Description, i, test.Hash, out[:])
		}
	}
}

func BenchmarkNH(b *testing.B) {
	msg := make([]byte, 4096)
	rand.Read(msg)
	key := make([]byte, len(msg)+48)
	rand.Read(key)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out [32]byte
		Sum(&out, msg, key)
	}
}
