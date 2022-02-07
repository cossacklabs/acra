//go:build !go1.16
// +build !go1.16

package filesystem

import (
	"errors"
	keystore2 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"os"
)

// IsKeyReadError return true if error is os.ErrNotExist compatible and NoKeyFoundExit
func IsKeyReadError(err error) bool {
	// TODO remove this file after removing go1.15 support. Read os.IsNotExist docs that suggest change to this
	// return (errors.Is(err, fs.ErrNotExist) || errors.Is(err, api.ErrNotExist)) && keystore2.NoKeyFoundExit

	// use os.IsNotExist twice because it doesn't support properly wrapped errors until go1.16
	//return ((os.IsNotExist(err) || os.IsNotExist(errors.Unwrap(err))) || errors.Is(err, api.ErrNotExist)) && keystore2.NoKeyFoundExit
	return ((os.IsNotExist(err)) || errors.Is(err, api.ErrNotExist)) && keystore2.NoKeyFoundExit
}
