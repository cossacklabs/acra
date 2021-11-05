package hmac

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestExtractHash(t *testing.T) {
	data := make([]byte, 100)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	someKey := []byte(`key`)
	hashData := GenerateHMAC(someKey, data)
	h := ExtractHash(hashData)
	if h == nil {
		t.Fatal("Invalid hash value")
	}
	// 1 byte of hash ID
	expectedSize := 1 + sha256.Size
	if h.Length() != expectedSize {
		t.Fatal("Invalid hmac size")
	}
}

func TestExtractHashAndData(t *testing.T) {
	data := make([]byte, 100)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	someKey := []byte(`key`)
	hashData := GenerateHMAC(someKey, data)
	testData := append(hashData, data...)
	h, container := ExtractHashAndData(testData)
	if h == nil {
		t.Fatal("Invalid hash value")
	}
	if !bytes.Equal(container, data) {
		t.Fatal("Incorrect extraction of data")
	}
	// 1 byte of hash ID
	expectedSize := 1 + sha256.Size
	if h.Length() != expectedSize {
		t.Fatal("Invalid hmac size")
	}
}
