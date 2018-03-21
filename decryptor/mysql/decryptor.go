package mysql

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

type decryptFunc func([]byte) ([]byte, error)

type MySQLDecryptor struct {
	base.Decryptor
	binaryDecryptor *binary.BinaryDecryptor
	keyStore        keystore.KeyStore
	decryptFunc     decryptFunc
	log             *log.Entry
}

const (
	DECRYPT_WHOLE  = "whole_block"
	DECRYPT_INLINE = "inline_block"
)

func NewMySQLDecryptor(pgDecryptor *postgresql.PgDecryptor, keyStore keystore.KeyStore) *MySQLDecryptor {
	decryptor := &MySQLDecryptor{keyStore: keyStore, binaryDecryptor: binary.NewBinaryDecryptor(), Decryptor: pgDecryptor}
	decryptor.log = log.WithField("decryptor", "mysql")
	decryptor.SetWholeMatch(pgDecryptor.IsWholeMatch())
	return decryptor
}

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

func (decryptor *MySQLDecryptor) ReadData(symmetricKey, zoneId []byte, reader io.Reader) ([]byte, error) {
	return decryptor.binaryDecryptor.ReadData(symmetricKey, zoneId, reader)
}

func (decryptor *MySQLDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.binaryDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

func (decryptor *MySQLDecryptor) getPoisonPrivateKey() (*keys.PrivateKey, error) {
	keypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}
	return keypair.Private, nil
}

// CheckPoisonRecord check data from reader on poison records
// added to implement base.Decryptor interface
func (decryptor *MySQLDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	block, err := ioutil.ReadAll(reader)
	if err != nil {
		return false, err
	}
	return decryptor.checkPoisonRecord(block)
}

func (decryptor *MySQLDecryptor) checkPoisonRecord(block []byte) (bool, error) {
	decryptor.Reset()
	data, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		log.WithError(err).Debugln("can't skip begin tag in block")
		return false, nil
	}
	if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
		log.Debugln("check block on poison")
		_, err := decryptor.decryptBlock(bytes.NewReader(data), nil, decryptor.getPoisonPrivateKey)
		if err == nil {
			log.Warningln("recognized poison record")
			if err := decryptor.GetPoisonCallbackStorage().Call(); err != nil {
				log.WithError(err).Errorln("unexpected error in poison record callbacks")
			}
			log.Debugln("processed all callbacks on poison record")
			return true, err
		}
	}
	return false, nil
}

// poisonCheck find acrastructs in block and try to detect poison record
func (decryptor *MySQLDecryptor) poisonCheck(block []byte) error {
	log.Debugln("check poison records")
	index := 0
	for {
		beginTagIndex, _ := decryptor.BeginTagIndex(block[index:])
		if beginTagIndex == utils.NOT_FOUND {
			break
		} else {
			log.Debugln("found acrastruct")
			poisoned, err := decryptor.checkPoisonRecord(block[index+beginTagIndex:])
			if poisoned {
				return base.ErrPoisonRecord
			}
			return err
		}
		index++
	}
	return nil
}

type getKeyFunc func() (*keys.PrivateKey, error)

// decryptBlock try to process data after BEGIN_TAG, decrypt and return result
func (decryptor *MySQLDecryptor) decryptBlock(reader io.Reader, id []byte, keyFunc getKeyFunc) ([]byte, error) {
	privateKey, err := keyFunc()
	if err != nil {
		decryptor.log.Warningln("can't read private key")
		return []byte{}, err
	}
	key, _, err := decryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		decryptor.log.Warningf("%v", utils.ErrorMessage("can't unwrap symmetric key", err))
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, id, reader)
	if err != nil {
		decryptor.log.Warningf("%v", utils.ErrorMessage("can't decrypt data with unwrapped symmetric key", err))
		return []byte{}, err
	}
	return data, nil
}

func (decryptor *MySQLDecryptor) SetWholeMatch(value bool) {
	if value {
		decryptor.decryptFunc = decryptor.decryptWholeBlock
		decryptor.log = decryptor.log.WithField("decrypt_mode", DECRYPT_WHOLE)
	} else {
		decryptor.decryptFunc = decryptor.decryptInlineBlock
		decryptor.log = decryptor.log.WithField("decrypt_mode", DECRYPT_INLINE)
	}
}

func (decryptor *MySQLDecryptor) decryptWholeBlock(block []byte) ([]byte, error) {
	var err error
	if err := decryptor.poisonCheck(block); err != nil {
		return nil, err
	}
	decryptor.Reset()
	if !decryptor.IsWithZone() || decryptor.IsMatchedZone() {
		block, err = decryptor.SkipBeginInBlock(block)
		if err != nil {
			return nil, err
		}
		newData, err := decryptor.decryptBlock(bytes.NewReader(block), decryptor.GetMatchedZoneId(), decryptor.GetPrivateKey)
		if decryptor.IsWithZone() && err == nil && len(newData) != len(block) {
			decryptor.ResetZoneMatch()
		}
		return newData, err
	} else {
		decryptor.MatchZoneBlock(block)
		return block, nil
	}
}

func (decryptor *MySQLDecryptor) decryptInlineBlock(block []byte) ([]byte, error) {
	if err := decryptor.poisonCheck(block); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	index := 0
	log.Debugf("block len %v", len(block))
	if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
		decryptor.MatchZoneInBlock(block)
		return block, nil
	}
	for index < len(block) {
		log.Debugf("index=%v", index)
		decryptor.log.Debugf("index: %v", index)
		beginTagIndex, tagLength := decryptor.BeginTagIndex(block[index:])
		if beginTagIndex == utils.NOT_FOUND {
			output.Write(block[index:])
			return output.Bytes(), nil
		}
		output.Write(block[index : index+beginTagIndex])
		index += beginTagIndex
		blockReader := bytes.NewReader(block[index+tagLength:])
		decrypted, err := decryptor.decryptBlock(blockReader, decryptor.GetMatchedZoneId(), decryptor.GetPrivateKey)
		if err != nil {
			output.Write(block[index : index+1])
			index++
			decryptor.log.Debugln("can't decrypt block")
			continue
		}
		index += tagLength + (len(block[beginTagIndex+tagLength:]) - blockReader.Len())
		output.Write(decrypted)
		decryptor.ResetZoneMatch()
	}
	return output.Bytes(), nil
}

func (decryptor *MySQLDecryptor) DecryptBlock(block []byte) ([]byte, error) {
	return decryptor.decryptFunc(block)
}
