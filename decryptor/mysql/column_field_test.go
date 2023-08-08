package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFieldFlag(t *testing.T) {
	flag := Flags(4241)
	assert.True(t, flag.ContainsFlag(BlobFlag))
	assert.True(t, flag.ContainsFlag(NoDefaultValueFlag))

	flag.RemoveFlag(BlobFlag)
	assert.False(t, flag.ContainsFlag(BlobFlag))
	assert.True(t, flag.ContainsFlag(NoDefaultValueFlag))
}
