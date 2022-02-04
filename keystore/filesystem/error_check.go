//go:build go1.16
// +build go1.16

package filesystem

import (
	"errors"
	keystore2 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"io/fs"
	"os"
)

// IsKeyReadError return true if error is os.ErrNotExist compatible and NoKeyFoundExit
func IsKeyReadError(err error) bool {
	return (errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) || errors.Is(err, api.ErrNotExist)) && keystore2.NoKeyFoundExit
}
