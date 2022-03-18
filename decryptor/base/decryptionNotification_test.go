package base

import (
	"context"
	"testing"
)

func TestMarkDecryptedContext(t *testing.T) {
	ctx := context.Background()
	if IsDecryptedFromContext(ctx) {
		t.Fatal("Unexpected decrypted flag")
	}
	ctx = MarkDecryptedContext(ctx)
	if !IsDecryptedFromContext(ctx) {
		t.Fatal("Expects decrypted flag")
	}
}
