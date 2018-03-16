package mysql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
)

type MySQLDecryptor struct {
	*postgresql.PgDecryptor
	binaryDecryptor *binary.BinaryDecryptor
	keyStore        keystore.KeyStore
}

func NewMySQLDecryptor(pgDecryptor *postgresql.PgDecryptor, keyStore keystore.KeyStore) *MySQLDecryptor {
	return &MySQLDecryptor{keyStore: keyStore, binaryDecryptor: binary.NewBinaryDecryptor(), PgDecryptor: pgDecryptor}
}

//DecryptBlock([]byte) ([]byte, error)

func (decryptor *MySQLDecryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
	n := 0
	for _, c := range block {
		if !decryptor.MatchBeginTag(c) {
			return []byte{}, base.ErrFakeAcraStruct
		}
		n++
		if decryptor.IsMatched() {
			break
		}
	}

	if !decryptor.IsMatched() {
		return []byte{}, base.ErrFakeAcraStruct
	}
	return block[n:], nil
}
func (decryptor *MySQLDecryptor) MatchZoneBlock(block []byte) {
	for _, c := range block {
		if !decryptor.MatchZone(c) {
			return
		}
	}
}
func (decryptor *MySQLDecryptor) BeginTagIndex(block []byte) (int, int) {
	if i := utils.FindTag(base.TAG_SYMBOL, decryptor.binaryDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	return utils.NOT_FOUND, decryptor.GetTagBeginLength()
}

func (decryptor *MySQLDecryptor) MatchZoneInBlock(block []byte) {
	for {
		// binary format
		i := utils.FindTag(zone.ZONE_TAG_SYMBOL, zone.ZONE_TAG_LENGTH, block)
		if i == utils.NOT_FOUND {
			break
		} else {
			if decryptor.keyStore.HasZonePrivateKey(block[i : i+zone.ZONE_ID_BLOCK_LENGTH]) {
				decryptor.GetZoneMatcher().SetMatched(block[i : i+zone.ZONE_ID_BLOCK_LENGTH])
				return
			}
			block = block[i+1:]
		}
	}
	return
}
