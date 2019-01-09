package mysql

import (
	"encoding/base64"
	"testing"

	"crypto/rand"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type testKeystore struct {
	PoisonKeypair *keys.Keypair
}

func (*testKeystore) RotateZoneKey(zoneID []byte) ([]byte, error) {
	panic("implement me")
}
func (keystore *testKeystore) GetPoisonKeyPair() (*keys.Keypair, error) {
	return keystore.PoisonKeypair, nil
}

func (keystore *testKeystore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return nil, nil
}
func (keystore *testKeystore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	return nil, nil
}
func (keystore *testKeystore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	return nil, nil
}
func (keystore *testKeystore) HasZonePrivateKey(id []byte) bool {
	return true
}
func (keystore *testKeystore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return nil, nil
}
func (keystore *testKeystore) GenerateZoneKey() ([]byte, []byte, error) {
	return nil, nil, nil
}
func (keystore *testKeystore) GenerateConnectorKeys(id []byte) error {
	return nil
}
func (keystore *testKeystore) GenerateServerKeys(id []byte) error {
	return nil
}
func (keystore *testKeystore) GenerateTranslatorKeys(id []byte) error {
	return nil
}
func (keystore *testKeystore) GenerateDataEncryptionKeys(id []byte) error {
	return nil
}
func (keystore *testKeystore) GetAuthKey(remove bool) ([]byte, error) {
	return nil, nil
}
func (keystore *testKeystore) Reset() {}
func (*testKeystore) SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveTranslatorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveServerKeypair(id []byte, keypair *keys.Keypair) error { panic("implement me") }
func (*testKeystore) SaveConnectorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveZoneKeypair(id []byte, keypair *keys.Keypair) error { panic("implement me") }
func (*testKeystore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	panic("implement me")
}
func (*testKeystore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) { panic("implement me") }

func getDecryptor(keystore keystore.KeyStore) *MySQLDecryptor {
	dataDecryptor := binary.NewBinaryDecryptor()
	clientID := []byte("some id")
	pgDecryptor := postgresql.NewPgDecryptor(clientID, dataDecryptor, false, keystore)
	decryptor := NewMySQLDecryptor(clientID, pgDecryptor, keystore)

	poisonCallbackStorage := base.NewPoisonCallbackStorage()
	decryptor.SetPoisonCallbackStorage(poisonCallbackStorage)
	return decryptor
}

func TestMySQLDecryptor_CheckPoisonRecord_Inline(t *testing.T) {
	poisonKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		panic(err)
	}
	tkeystore := &testKeystore{PoisonKeypair: poisonKeypair}
	decryptor := getDecryptor(tkeystore)

	part1 := make([]byte, 1024)
	part2 := make([]byte, 1024)
	if _, err := rand.Read(part1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(part2); err != nil {
		t.Fatal(err)
	}

	poisonRecord, err := poison.CreatePoisonRecord(tkeystore, 1024)
	if err != nil {
		t.Fatal(err)
	}

	testData := append(part1, append(poisonRecord, part2...)...)
	err = decryptor.inlinePoisonRecordCheck(testData)
	if err != base.ErrPoisonRecord {
		t.Logf("test_data=%v\npoison_record=%v\npoison_public=%v\npoison_private=%v", base64.StdEncoding.EncodeToString(testData), base64.StdEncoding.EncodeToString(poisonRecord),
			base64.StdEncoding.EncodeToString(poisonKeypair.Public.Value), base64.StdEncoding.EncodeToString(poisonKeypair.Private.Value))
		t.Fatal("expected ErrPoisonRecord")
	}
}

func TestMySQLDecryptor_CheckPoisonRecord_Block(t *testing.T) {
	poisonKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		panic(err)
	}
	tkeystore := &testKeystore{PoisonKeypair: poisonKeypair}
	decryptor := getDecryptor(tkeystore)

	poisonRecord, err := poison.CreatePoisonRecord(tkeystore, 1024)
	if err != nil {
		t.Fatal(err)
	}
	err = decryptor.inlinePoisonRecordCheck(poisonRecord)
	if err != base.ErrPoisonRecord {
		t.Fatal("expected ErrPoisonRecord")
	}
}
