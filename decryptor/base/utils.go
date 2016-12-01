package base

import (
	"bytes"
	"encoding/binary"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

const (
	LENGTH_SIZE = 8
)

func DecryptAcrastruct(data []byte, private_key *keys.PrivateKey, zone []byte) ([]byte, error) {
	inner_data := data[len(TAG_BEGIN):]
	pubkey := &keys.PublicKey{Value: inner_data[:PUBLIC_KEY_LENGTH]}
	smessage := message.New(private_key, pubkey)
	symmetric_key, err := smessage.Unwrap(inner_data[PUBLIC_KEY_LENGTH:KEY_BLOCK_LENGTH])
	if err != nil {
		return []byte{}, err
	}
	//
	var length uint64
	// convert from little endian
	err = binary.Read(bytes.NewReader(inner_data[KEY_BLOCK_LENGTH:KEY_BLOCK_LENGTH+LENGTH_SIZE]), binary.LittleEndian, &length)
	if err != nil {
		return []byte{}, err
	}
	scell := cell.New(symmetric_key, cell.CELL_MODE_SEAL)
	decrypted, err := scell.Unprotect(inner_data[KEY_BLOCK_LENGTH+LENGTH_SIZE:], nil, zone)
	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetric_key)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}
