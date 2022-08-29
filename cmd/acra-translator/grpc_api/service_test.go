/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package grpc_api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	translatorCommon "github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/utils/tests"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/pseudonymization"
	storage2 "github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

func interfaceToRequestValue(d interface{}) isTokenizeRequest_Value {
	switch val := d.(type) {
	case []byte:
		return &TokenizeRequest_BytesValue{val}
	case string:
		return &TokenizeRequest_StrValue{val}
	case common.Email:
		return &TokenizeRequest_EmailValue{string(val)}
	case int32:
		return &TokenizeRequest_Int32Value{val}
	case int64:
		return &TokenizeRequest_Int64Value{val}
	default:
		panic("invalid value")
	}
}

func responseToRequest(resp *TokenizeResponse) isTokenizeRequest_Value {
	switch val := resp.Response.(type) {
	case *TokenizeResponse_BytesToken:
		return &TokenizeRequest_BytesValue{val.BytesToken}
	case *TokenizeResponse_StrToken:
		return &TokenizeRequest_StrValue{val.StrToken}
	case *TokenizeResponse_Int32Token:
		return &TokenizeRequest_Int32Value{val.Int32Token}
	case *TokenizeResponse_Int64Token:
		return &TokenizeRequest_Int64Value{val.Int64Token}
	case *TokenizeResponse_EmailToken:
		return &TokenizeRequest_EmailValue{val.EmailToken}
	default:
		panic("invalid value")
	}
}
func isEqualDataWithTokenizeResponse(data1 interface{}, resp *TokenizeResponse) bool {
	switch val := resp.Response.(type) {
	case *TokenizeResponse_BytesToken:
		d, ok := data1.([]byte)
		if !ok {
			return false
		}
		return bytes.Equal(d, val.BytesToken)
	case *TokenizeResponse_StrToken:
		d, ok := data1.(string)
		if !ok {
			return false
		}
		return d == val.StrToken
	case *TokenizeResponse_Int32Token:
		d, ok := data1.(int32)
		if !ok {
			return false
		}
		return d == val.Int32Token
	case *TokenizeResponse_Int64Token:
		d, ok := data1.(int64)
		if !ok {
			return false
		}
		return d == val.Int64Token
	case *TokenizeResponse_EmailToken:
		d, ok := data1.(common.Email)
		if !ok {
			return false
		}
		return d == common.Email(val.EmailToken)
	default:
		panic("invalid value")
	}
}

func TestTranslatorServiceMemory(t *testing.T) {
	storage, err := storage2.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}
	testTranslatorService(storage, t)
}

func testTranslatorService(storage common.TokenStorage, t *testing.T) {
	tokenizer, err := pseudonymization.NewPseudoanonymizer(storage)
	if err != nil {
		t.Fatal(err)
	}
	translatorData := &translatorCommon.TranslatorData{tokenizer, nil, nil, nil, false, nil}
	serviceImplementation, err := translatorCommon.NewTranslatorService(translatorData)
	if err != nil {
		t.Fatal(err)
	}
	service := &TranslatorService{service: serviceImplementation, logger: logrus.NewEntry(logrus.StandardLogger())}
	testValues := []interface{}{
		[]byte(`test data`),
		"test data",
		common.Email("test email"),
		int32(1),
		int64(2),
	}
	clientID := []byte(`client id`)
	// zoneID := []byte(`zone id`)
	ctx := context.Background()
	for _, data := range testValues {
		for i := 0; i < 5; i++ {
			tokenized, err := service.Tokenize(ctx, &TokenizeRequest{ClientId: clientID, Value: interfaceToRequestValue(data)})
			if err != nil {
				t.Fatal(err)
			}

			detokenized, err := service.Detokenize(ctx, &TokenizeRequest{ClientId: clientID, Value: responseToRequest(tokenized)})
			if err != nil {
				t.Fatal(err)
			}
			if !isEqualDataWithTokenizeResponse(data, detokenized) {
				t.Fatal("Incorrect tokenization/detokenization")
			}
		}
	}
}

func TestTranslatorService_Search(t *testing.T) {
	type testCase struct {
		ClientID []byte
		ZoneID   []byte
		Data     []byte
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatal(err)
	}
	clientIDKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	zoneIDKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keystore := &mocks.ServerKeyStore{}
	// return copy of all private keys because of their erasing on every usage by clients
	keystore.On("GetHMACSecretKey", mock.MatchedBy(func([]byte) bool { return true })).Return(func([]byte) []byte { return append([]byte{}, hmacKey...) }, nil)
	keystore.On("GetZonePrivateKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) []*keys.PrivateKey {
			return []*keys.PrivateKey{&keys.PrivateKey{Value: append([]byte{}, zoneIDKeypair.Private.Value...)}}
		},
		nil)
	keystore.On("GetServerDecryptionPrivateKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) []*keys.PrivateKey {
			return []*keys.PrivateKey{&keys.PrivateKey{Value: append([]byte{}, clientIDKeypair.Private.Value...)}}
		},
		nil)
	keystore.On("GetZonePublicKey", mock.MatchedBy(func([]byte) bool { return true })).Return(zoneIDKeypair.Public, nil)
	keystore.On("GetClientIDEncryptionPublicKey", mock.MatchedBy(func([]byte) bool { return true })).Return(clientIDKeypair.Public, nil)
	translatorData := &translatorCommon.TranslatorData{PoisonRecordCallbacks: poison.NewCallbackStorage(), Keystorage: keystore}
	serviceImplementation, err := translatorCommon.NewTranslatorService(translatorData)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewTranslatorService(serviceImplementation, translatorData)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{[]byte(`client id 1`), nil, []byte(`data1`)},
		{[]byte(`client id 2`), []byte(`zone id 1`), []byte(`data2`)},
	}
	ctx := context.Background()
	for _, tcase := range testCases {
		EncryptSearchableResponse, err := service.EncryptSearchable(ctx, &SearchableEncryptionRequest{ClientId: tcase.ClientID, Data: tcase.Data})
		if err != nil {
			t.Fatal(err)
		}
		hashResponse, err := service.GenerateQueryHash(ctx, &QueryHashRequest{ClientId: tcase.ClientID, Data: tcase.Data})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(EncryptSearchableResponse.Hash, hashResponse.Hash) {
			t.Fatal("Hash after EncryptSearchable operation not equal with GenerateQueryHash operation")
		}
		// try to decrypt correct AcraStruct with incorrect hash
		decryptedResponseWithoutHash, err := service.DecryptSearchable(ctx, &SearchableDecryptionRequest{ClientId: tcase.ClientID, Data: EncryptSearchableResponse.Acrastruct, Hash: []byte(`invalid hash`)})
		if err == nil {
			t.Fatal("expect error related to invalid hash")
		}
		if decryptedResponseWithoutHash != nil && decryptedResponseWithoutHash.Data != nil {
			t.Fatal("exposed data after decryption after used invalid hash")
		}

		acrastructWithHash := append(EncryptSearchableResponse.Hash, EncryptSearchableResponse.Acrastruct...)
		decryptedResponseWithoutHash, err = service.DecryptSearchable(ctx, &SearchableDecryptionRequest{ClientId: tcase.ClientID, Data: acrastructWithHash, Hash: nil})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedResponseWithoutHash.Data, tcase.Data) {
			t.Fatal("decrypted data without hash not equal to raw data")
		}
		decryptedResponseWithHash, err := service.DecryptSearchable(ctx, &SearchableDecryptionRequest{ClientId: tcase.ClientID, Data: EncryptSearchableResponse.Acrastruct, Hash: EncryptSearchableResponse.Hash})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedResponseWithHash.Data, tcase.Data) {
			t.Fatal("decrypted data with hash not equal to raw data")
		}
	}
}

func TestTranslatorService_SearchSym(t *testing.T) {
	type testCase struct {
		ClientID []byte
		ZoneID   []byte
		Data     []byte
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatal(err)
	}
	clientIDSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	zoneIDSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	keystore := &mocks.ServerKeyStore{}
	keystore.On("GetHMACSecretKey", mock.MatchedBy(func([]byte) bool { return true })).Return(func([]byte) []byte { return append([]byte{}, hmacKey...) }, nil)
	keystore.On("GetZoneIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) [][]byte {
			return [][]byte{append([]byte{}, zoneIDSymKey...)}
		},
		nil)
	keystore.On("GetZoneIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) []byte {
			return append([]byte{}, zoneIDSymKey...)
		},
		nil)
	keystore.On("GetClientIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) [][]byte {
			return [][]byte{append([]byte{}, clientIDSymKey...)}
		},
		nil)
	keystore.On("GetClientIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
		func([]byte) []byte {
			return append([]byte{}, clientIDSymKey...)
		},
		nil)

	translatorData := &translatorCommon.TranslatorData{Keystorage: keystore}
	serviceImplementation, err := translatorCommon.NewTranslatorService(translatorData)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewTranslatorService(serviceImplementation, translatorData)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{[]byte(`client id 1`), nil, []byte(`data1`)},
		{[]byte(`client id 2`), []byte(`zone id 1`), []byte(`data2`)},
	}
	ctx := context.Background()
	for _, tcase := range testCases {
		EncryptSearchableedResponse, err := service.EncryptSymSearchable(ctx, &SearchableSymEncryptionRequest{ClientId: tcase.ClientID, Data: tcase.Data})
		if err != nil {
			t.Fatal(err)
		}
		hashResponse, err := service.GenerateQueryHash(ctx, &QueryHashRequest{ClientId: tcase.ClientID, Data: tcase.Data})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(EncryptSearchableedResponse.Hash, hashResponse.Hash) {
			t.Fatal("Hash after EncryptSearchable operation not equal with GenerateQueryHash operation")
		}
		// try to decrypt correct AcraStruct with incorrect hash
		decryptedResponseWithoutHash, err := service.DecryptSymSearchable(ctx, &SearchableSymDecryptionRequest{ClientId: tcase.ClientID, Data: EncryptSearchableedResponse.Acrablock, Hash: []byte(`invalid hash`)})
		if err == nil {
			t.Fatal("expect error related to invalid hash")
		}
		if decryptedResponseWithoutHash != nil && decryptedResponseWithoutHash.Data != nil {
			t.Fatal("exposed data after decryption after used invalid hash")
		}

		acrastructWithHash := append(EncryptSearchableedResponse.Hash, EncryptSearchableedResponse.Acrablock...)
		decryptedResponseWithoutHash, err = service.DecryptSymSearchable(ctx, &SearchableSymDecryptionRequest{ClientId: tcase.ClientID, Data: acrastructWithHash, Hash: nil})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedResponseWithoutHash.Data, tcase.Data) {
			t.Fatal("decrypted data without hash not equal to raw data")
		}
		decryptedResponseWithHash, err := service.DecryptSymSearchable(ctx, &SearchableSymDecryptionRequest{ClientId: tcase.ClientID, Data: EncryptSearchableedResponse.Acrablock, Hash: EncryptSearchableedResponse.Hash})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedResponseWithHash.Data, tcase.Data) {
			t.Fatal("decrypted data with hash not equal to raw data")
		}
	}
}

type testPoisonCallback struct {
	called bool
}

func (t *testPoisonCallback) Call() error {
	t.called = true
	return nil
}

// poisonKeyStorageAndGeneratorStub provides a simple wrapper around
// mocks.ServerKeyStore. That's because the ServerKeyStore doesn't implement
// PoisonKeyStorageAndGenerator which we need to generate poison records.
type poisonKeyStorageAndGeneratorStub struct {
	keyStorage *mocks.ServerKeyStore
}

func (s *poisonKeyStorageAndGeneratorStub) GetPoisonKeyPair() (*keys.Keypair, error) {
	return s.keyStorage.GetPoisonKeyPair()
}
func (s *poisonKeyStorageAndGeneratorStub) GetPoisonPrivateKeys() ([]*keys.PrivateKey, error) {
	return s.keyStorage.GetPoisonPrivateKeys()
}
func (s *poisonKeyStorageAndGeneratorStub) GetPoisonSymmetricKeys() ([][]byte, error) {
	return s.keyStorage.GetPoisonSymmetricKeys()
}
func (s *poisonKeyStorageAndGeneratorStub) GetPoisonSymmetricKey() ([]byte, error) {
	return s.keyStorage.GetPoisonSymmetricKey()
}
func (s *poisonKeyStorageAndGeneratorStub) GeneratePoisonSymmetricKey() error {
	return nil
}
func (s *poisonKeyStorageAndGeneratorStub) GeneratePoisonKeyPair() error {
	return nil
}

func TestTranslatorService_DecryptionPoisonRecord(t *testing.T) {
	type testCase struct {
		ClientID []byte
		ZoneID   []byte
		Data     []byte
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatal(err)
	}
	someSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	poisonSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	keyStorage := &mocks.ServerKeyStore{}
	// everytime return copy of value because it will be zeroized after each call
	keyStorage.On("GetPoisonSymmetricKeys").Return(func() [][]byte { return [][]byte{append([]byte{}, poisonSymKey...)} }, nil)
	keyStorage.On("GetPoisonSymmetricKey").Return(func() []byte { return append([]byte{}, poisonSymKey...) }, nil)
	callbackStorage := poison.NewCallbackStorage()
	callback := &testPoisonCallback{}
	callbackStorage.AddCallback(callback)
	translatorData := &translatorCommon.TranslatorData{PoisonRecordCallbacks: callbackStorage, Keystorage: keyStorage}
	serviceImplementation, err := translatorCommon.NewTranslatorService(translatorData)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewTranslatorService(serviceImplementation, translatorData)
	if err != nil {
		t.Fatal(err)
	}
	poisonRecord, err := poison.CreateSymmetricPoisonRecord(&poisonKeyStorageAndGeneratorStub{keyStorage}, 100)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []testCase{
		{[]byte(`client id 1`), nil, poisonRecord},
		{[]byte(`client id 2`), []byte(`zone id 1`), poisonRecord},
	}
	ctx := context.Background()
	t.Run("DecryptSymSearchable with poison record", func(t *testing.T) {
		// reset all .On registered callbacks
		keyStorage.ExpectedCalls = nil
		keyStorage.On("GetPoisonSymmetricKeys").Return(func() [][]byte { return [][]byte{append([]byte{}, poisonSymKey...)} }, nil)
		keyStorage.On("GetPoisonSymmetricKey").Return(func() []byte { return append([]byte{}, poisonSymKey...) }, nil)
		keyStorage.On("GetHMACSecretKey", mock.MatchedBy(func([]byte) bool { return true })).Return(func([]byte) []byte { return append([]byte{}, hmacKey...) }, nil)
		keyStorage.On("GetZoneIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) [][]byte {
				return [][]byte{append([]byte{}, someSymKey...)}
			},
			nil)
		keyStorage.On("GetZoneIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) []byte {
				return append([]byte{}, someSymKey...)
			},
			nil)
		keyStorage.On("GetClientIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) [][]byte {
				return [][]byte{append([]byte{}, someSymKey...)}
			},
			nil)
		keyStorage.On("GetClientIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) []byte {
				return append([]byte{}, someSymKey...)
			},
			nil)
		for _, tcase := range testCases {
			// reset value in loop to re-use
			callback.called = false
			decryptedResponseWithoutHash, err := service.DecryptSymSearchable(ctx, &SearchableSymDecryptionRequest{ClientId: tcase.ClientID, Data: tcase.Data, Hash: nil})
			if err != ErrCantDecrypt {
				t.Fatalf("Expect ErrCantDecrypt, took %s\n", err)
			}
			if !callback.called {
				t.Fatal("Poison record callback wasn't call")
			}
			if decryptedResponseWithoutHash != nil {
				t.Fatalf("Result should be nil, but took %v\n", decryptedResponseWithoutHash)
			}
		}
	})
	t.Run("DecryptSym with poison record", func(t *testing.T) {
		// reset all .On registered callbacks
		keyStorage.ExpectedCalls = nil
		keyStorage.On("GetPoisonSymmetricKeys").Return(func() [][]byte { return [][]byte{append([]byte{}, poisonSymKey...)} }, nil)
		keyStorage.On("GetPoisonSymmetricKey").Return(func() []byte { return append([]byte{}, poisonSymKey...) }, nil)
		keyStorage.On("GetZoneIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) [][]byte {
				return [][]byte{append([]byte{}, someSymKey...)}
			},
			nil)
		keyStorage.On("GetZoneIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) []byte {
				return append([]byte{}, someSymKey...)
			},
			nil)
		keyStorage.On("GetClientIDSymmetricKeys", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) [][]byte {
				return [][]byte{append([]byte{}, someSymKey...)}
			},
			nil)
		keyStorage.On("GetClientIDSymmetricKey", mock.MatchedBy(func([]byte) bool { return true })).Return(
			func([]byte) []byte {
				return append([]byte{}, someSymKey...)
			},
			nil)
		for _, tcase := range testCases {
			// reset value in loop to re-use
			callback.called = false
			decryptedResponseWithoutHash, err := service.DecryptSym(ctx, &DecryptSymRequest{ClientId: tcase.ClientID, Acrablock: tcase.Data})
			if err != translatorCommon.ErrCantDecrypt {
				t.Fatalf("Expect ErrCantDecrypt, took %s\n", err)
			}
			if !callback.called {
				t.Fatal("Poison record callback wasn't call")
			}
			if decryptedResponseWithoutHash != nil {
				t.Fatalf("Result should be nil, but took %v\n", decryptedResponseWithoutHash)
			}
		}
	})
}

const connectionTimeout = time.Second

// testgRPCServer start gRPC server as gorountine using unix socket
type testgRPCServer struct {
	listener net.Listener
	server   *grpc.Server
	unixPath string
}

func newTokenizer(t *testing.T) common.Pseudoanonymizer {
	tokenStore, err := storage2.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}
	tokenizer, err := pseudonymization.NewPseudoanonymizer(tokenStore)
	if err != nil {
		t.Fatal(err)
	}
	return tokenizer
}

func newServer(data *translatorCommon.TranslatorData, wrapper network.GRPCConnectionWrapper, t *testing.T) *testgRPCServer {
	server, err := NewServer(data, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	unixPath, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(unixPath.Name())
	listener, err := net.Listen("unix", unixPath.Name())
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	return &testgRPCServer{listener: listener, server: server, unixPath: unixPath.Name()}
}

// newServerTLSgRPCOpts returns server options to use TLS as transport using keys from tests/ssl/[ca|acra-server]
func newServerTLSgRPCOpts(t *testing.T, idExtractor network.TLSClientIDExtractor) network.GRPCConnectionWrapper {
	verifier := network.NewCertVerifierAll()
	workingDirectory := tests.GetSourceRootDirectory(t)
	serverConfig, err := network.NewTLSConfig("localhost", filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"), filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.key"), filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.crt"), 4, verifier)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := network.NewTLSAuthenticationConnectionWrapper(true, nil, serverConfig, idExtractor)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func newClientTLSConfig(t *testing.T) *tls.Config {
	verifier := network.NewCertVerifierAll()
	workingDirectory := tests.GetSourceRootDirectory(t)
	clientConfig, err := network.NewTLSConfig("localhost", filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"), 4, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return clientConfig
}

func newClientTLSgRPCOpts(config *tls.Config, t *testing.T) []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(config))}
}

func (server *testgRPCServer) Stop() {
	server.server.Stop()
	server.listener.Close()
}

func getgRPCUnixDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", addr)
	})
}

func (server *testgRPCServer) NewConnection(opts []grpc.DialOption, t *testing.T) *grpc.ClientConn {
	ctx, _ := context.WithTimeout(context.Background(), connectionTimeout)
	conn, err := grpc.DialContext(ctx, server.unixPath, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestNewFactoryWithClientIDFromTLSConnection(t *testing.T) {
	idConvertor, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	idExtractor, err := network.NewTLSClientIDExtractor(&network.DistinguishedNameExtractor{}, idConvertor)
	if err != nil {
		t.Fatal(err)
	}

	keystorage := &mocks.TranslationKeyStore{}

	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout*5)
	defer cancel()
	data := &translatorCommon.TranslatorData{UseConnectionClientID: true, Keystorage: keystorage, Tokenizer: newTokenizer(t)}
	wrapper := newServerTLSgRPCOpts(t, idExtractor)
	server := newServer(data, wrapper, t)
	defer server.Stop()
	clientConfig := newClientTLSConfig(t)
	clientOpts := newClientTLSgRPCOpts(clientConfig, t)
	clientOpts = append(clientOpts, getgRPCUnixDialer())
	conn := server.NewConnection(clientOpts, t)
	defer conn.Close()

	x509ClientCert, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientID, err := idExtractor.ExtractClientID(x509ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	testgRPCServiceFlow(ctx, expectedClientID, conn, keystorage, t)
}

func testgRPCServiceFlow(ctx context.Context, expectedClientID []byte, conn *grpc.ClientConn, keystorage *mocks.TranslationKeyStore, t *testing.T) {
	testKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	testSymmetricKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	keystorage.On("GetClientIDEncryptionPublicKey", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, expectedClientID)
	})).Return(testKeypair.Public, nil)

	keystorage.On("GetServerDecryptionPrivateKeys", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, expectedClientID)
	})).Return(
		func([]byte) []*keys.PrivateKey {
			return []*keys.PrivateKey{{Value: append([]byte{}, testKeypair.Private.Value...)}}
		},
		nil)

	writerClient := NewWriterClient(conn)
	encryptResponse, err := writerClient.Encrypt(ctx, &EncryptRequest{Data: testData})
	if err != nil {
		t.Fatal(err)
	}

	readerClient := NewReaderClient(conn)
	decryptResponse, err := readerClient.Decrypt(ctx, &DecryptRequest{Acrastruct: encryptResponse.Acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testData, decryptResponse.Data)

	keystorage.On("GetClientIDSymmetricKeys", mock.Anything).Return(
		func([]byte) [][]byte {
			return [][]byte{append([]byte{}, testSymmetricKey...)}
		},
		nil)
	keystorage.On("GetClientIDSymmetricKey", mock.Anything).Return(
		func([]byte) []byte {
			return append([]byte{}, testSymmetricKey...)
		},
		nil)
	symWriterClient := NewWriterSymClient(conn)
	symEncryptResponse, err := symWriterClient.EncryptSym(ctx, &EncryptSymRequest{Data: testData})
	if err != nil {
		t.Fatal(err)
	}

	symReaderClient := NewReaderSymClient(conn)
	symDecryptResponse, err := symReaderClient.DecryptSym(ctx, &DecryptSymRequest{Acrablock: symEncryptResponse.Acrablock})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testData, symDecryptResponse.Data)

	tokenClient := NewTokenizatorClient(conn)
	tokenizeResponse, err := tokenClient.Tokenize(ctx, &TokenizeRequest{Value: &TokenizeRequest_BytesValue{
		testData,
	}})
	if err != nil {
		t.Fatal(err)
	}
	detokenizeResponse, err := tokenClient.Detokenize(ctx, &TokenizeRequest{Value: &TokenizeRequest_BytesValue{
		tokenizeResponse.GetBytesToken(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testData, detokenizeResponse.GetBytesToken())

	keystorage.On("GetHMACSecretKey", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(expectedClientID, id)
	})).Return(
		func([]byte) []byte { return append([]byte{}, testSymmetricKey...) },
		nil)
	searchableClient := NewSearchableEncryptionClient(conn)
	_, _ = searchableClient.GenerateQueryHash(ctx, &QueryHashRequest{Data: testData})
}

func TestNewFactoryWithClientIDFromSecureSessionConnectionInvalidAuthInfo(t *testing.T) {
	keystorage := &mocks.TranslationKeyStore{}
	data := &translatorCommon.TranslatorData{UseConnectionClientID: true, Keystorage: keystorage, Tokenizer: newTokenizer(t)}
	server := newServer(data, nil, t)
	defer server.Stop()
	clientOpts := []grpc.DialOption{grpc.WithInsecure(), getgRPCUnixDialer()}
	conn := server.NewConnection(clientOpts, t)
	defer conn.Close()

	writerClient := NewWriterClient(conn)
	testdata := []byte("some data")
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	_, err := writerClient.Encrypt(ctx, &EncryptRequest{Data: testdata})
	grpcErr, ok := status.FromError(err)
	if !ok {
		t.Fatal("incorrect error type, expected gRPC error")
	}
	if !strings.EqualFold(grpcErr.Message(), network.ErrCantExtractClientID.Error()) {
		t.Fatalf("incorrect error from gRPC request. took: %s, expects: %s\n", grpcErr.Message(), network.ErrCantExtractClientID)
	}

	readerClient := NewReaderClient(conn)
	_, err = readerClient.Decrypt(ctx, &DecryptRequest{Acrastruct: testdata})
	grpcErr, ok = status.FromError(err)
	if !ok {
		t.Fatal("incorrect error type, expected gRPC error")
	}
	if !strings.EqualFold(grpcErr.Message(), network.ErrCantExtractClientID.Error()) {
		t.Fatalf("incorrect error from gRPC request. took: %s, expects: %s\n", grpcErr.Message(), network.ErrCantExtractClientID)
	}
}

func init() {
	if err := crypto.InitRegistry(nil); err != nil {
		panic(err)
	}
}
