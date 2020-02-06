package http_api

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
)

func TestHTTPResponseStatus(t *testing.T) {
	keyStore := &testKeystore{}
	translatorData := &common.TranslatorData{Keystorage: keyStore, PoisonRecordCallbacks: base.NewPoisonCallbackStorage()}
	httpConnectionsDecryptor, err := NewHTTPConnectionsDecryptor(translatorData)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	//logging.SetLogLevel(logging.LOG_DEBUG)
	logger := log.NewEntry(log.StandardLogger())

	res := httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, nil, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If no Request -> Status code should be Bad Request, got %s\n", res.Status)
	}

	request := http.Request{}
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If no Requets URL -> Status code should be Bad Request, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/weird")
	request.Method = http.MethodGet
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("If not POST -> Status code should be StatusMethodNotAllowed, got %s\n", res.Status)
	}

	request.Method = http.MethodPost
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If URL has no version -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If URL has no /decrypt endpoint -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If Request has no body -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.Body = ioutil.NopCloser(bytes.NewBufferString("bla bla bla body"))
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If Request has no ZoneID and No ClientID -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1/decrypt?zone_id=\"somezoneid\"")
	request.Body = ioutil.NopCloser(bytes.NewBufferString("bla bla bla body"))
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, []byte("asdf"))
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("If Request Bad ZoneID and ClientID -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status)
	}
}

func TestHTTPDecryptionAndResponse(t *testing.T) {
	keyStore := &testKeystore{}
	translatorData := &common.TranslatorData{Keystorage: keyStore, PoisonRecordCallbacks: base.NewPoisonCallbackStorage(), CheckPoisonRecords: true}
	httpConnectionsDecryptor, err := NewHTTPConnectionsDecryptor(translatorData)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	//logging.SetLogLevel(logging.LOG_DEBUG)
	logger := log.NewEntry(log.StandardLogger())

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.EncryptionKeypair = keypair

	clientID := []byte("some client id")
	data := []byte("some data")

	// not an acrastruct
	request := http.Request{Method: http.MethodPost}
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte("some garbage not acrastruct")))

	res := httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(fmt.Sprintf("Should not be able to decrypt garbage -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status))
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	request = http.Request{Method: http.MethodPost}
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	request.Body = ioutil.NopCloser(bytes.NewBuffer(acrastruct))

	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf(fmt.Sprintf("Should be able to decrypt without zone -> Status code should be StatusOK, got %s\n", res.Status))
	}

	decryptedAcraStruct, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decryptedAcraStruct, data) {
		t.Fatal("Response data not equal to initial data")
	}

	// test with zone
	zoneID := clientID // use client id as zone id because no matter what to use
	acrastructWithZone, err := acrawriter.CreateAcrastruct(data, keypair.Public, zoneID)
	if err != nil {
		t.Fatal(err)
	}

	request = http.Request{Method: http.MethodPost}
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/decrypt?zone_id=%s", zoneID))
	request.Body = ioutil.NopCloser(bytes.NewBuffer(acrastructWithZone))

	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf(fmt.Sprintf("Should be able to decrypt with zone -> Status code should be StatusOK, got %s\n", res.Status))
	}

	decryptedAcraStructWithZone, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decryptedAcraStructWithZone, data) {
		t.Fatal("Response data not equal to initial data")
	}

	poisonKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.PoisonKeyPair = poisonKeyPair
	poisonRecord, err := poison.CreatePoisonRecord(keyStore, 50)
	if err != nil {
		t.Fatal(err)
	}
	testPoisonCallback := &poisonCallback{}
	translatorData.PoisonRecordCallbacks.AddCallback(testPoisonCallback)

	// check without zone
	request.Body = ioutil.NopCloser(bytes.NewReader(poisonRecord))
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(fmt.Sprintf("Should not be able to decrypt poison record -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status))
	}
	decryptedAcraStruct, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedAcraStruct, []byte("Can't decrypt AcraStruct")) {
		t.Fatal("Incorrect response body")
	}
	if !testPoisonCallback.Called {
		t.Fatal("Callback on poison record shouldn't be called")
	}
	testPoisonCallback.Called = false // reset

	// check with zone
	request.Body = ioutil.NopCloser(bytes.NewReader(poisonRecord))
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/decrypt?zone_id=%s", zoneID))
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(fmt.Sprintf("Should not be able to decrypt poison record -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status))
	}
	decryptedAcraStruct, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedAcraStruct, []byte("Can't decrypt AcraStruct")) {
		t.Fatal("Incorrect response body")
	}
	if !testPoisonCallback.Called {
		t.Fatal("Callback on poison record shouldn't be called")
	}

	// check that poison callbacks not processed when we turn off checks
	testPoisonCallback.Called = false
	translatorData.CheckPoisonRecords = false

	// check without zone
	request.Body = ioutil.NopCloser(bytes.NewReader(poisonRecord))
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(fmt.Sprintf("Should not be able to decrypt poison record -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status))
	}
	decryptedAcraStruct, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedAcraStruct, []byte("Can't decrypt AcraStruct")) {
		t.Fatal("Incorrect response body")
	}
	if testPoisonCallback.Called {
		t.Fatal("Callback on poison record shouldn't be called")
	}

	// check with zone
	request.Body = ioutil.NopCloser(bytes.NewReader(poisonRecord))
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/decrypt?zone_id=%s", zoneID))
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf(fmt.Sprintf("Should not be able to decrypt poison record -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status))
	}
	decryptedAcraStruct, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedAcraStruct, []byte("Can't decrypt AcraStruct")) {
		t.Fatal("Incorrect response body")
	}
	if testPoisonCallback.Called {
		t.Fatal("Callback on poison record shouldn't be called")
	}
}

func TestHTTPDecryptionAcraStruct(t *testing.T) {
	keyStore := &testKeystore{}
	translatorData := &common.TranslatorData{Keystorage: keyStore, PoisonRecordCallbacks: base.NewPoisonCallbackStorage()}
	httpConnectionsDecryptor, err := NewHTTPConnectionsDecryptor(translatorData)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.EncryptionKeypair = keypair

	clientID := []byte("some client id")
	data := []byte("some data")

	// not an acrastruct
	decrypted, err := httpConnectionsDecryptor.decryptAcraStruct(nil, []byte("some garbage not acrastruct"), nil, clientID)
	if err == nil || decrypted != nil {
		t.Fatalf("Should not be able to decrypt garbage")
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = httpConnectionsDecryptor.decryptAcraStruct(nil, acrastruct, nil, clientID)
	if err != nil {
		t.Fatalf("Should be able to decrypt acrastruct without zone")
	}

	if !bytes.Equal(decrypted, data) {
		t.Fatal("Decrypted acrastruct is not equal to initial data")
	}

	// test with zone
	zoneID := clientID // use client id as zone id because no matter what to use
	acrastructWithZone, err := acrawriter.CreateAcrastruct(data, keypair.Public, zoneID)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = httpConnectionsDecryptor.decryptAcraStruct(nil, acrastructWithZone, zoneID, clientID)
	if err != nil {
		t.Fatalf("Should be able to decrypt acrastruct with zone")
	}

	if !bytes.Equal(decrypted, data) {
		t.Fatal("Decrypted acrastruct is not equal to initial data")
	}
}

func TestHTTPEncryptionAndResponse(t *testing.T) {
	logger := log.NewEntry(log.StandardLogger())
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	clientID := []byte("some client id")
	data := []byte("some data")
	keyStore := &testKeystore{EncryptionKeypair: keypair, KeyID: clientID}
	translatorData := &common.TranslatorData{Keystorage: keyStore, CheckPoisonRecords: false}
	httpConnectionsDecryptor, err := NewHTTPConnectionsDecryptor(translatorData)
	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	// empty data
	request := http.Request{Method: http.MethodGet}
	request.URL, _ = url.Parse("http://smth.com/v1/encrypt")
	request.Body = nil

	res := httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf(fmt.Sprintf("Should not be able to process GET requests -> Status code should be MethodNotAllowed, got %s\n", res.Status))
	}

	request.Method = http.MethodPost

	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf(fmt.Sprintf("Should not be able to encrypt empty body -> Status code should be BadRequest, got %s\n", res.Status))
	}
	request.Body = ioutil.NopCloser(bytes.NewBuffer(data))

	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf(fmt.Sprintf("Should not be able to encrypt without client/zone id -> Status code should be BadRequest, got %s\n", res.Status))
	}

	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, []byte(`incorrect client id`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf(fmt.Sprintf("Should not be able to encrypt with incorrect client id -> Status code should be BadRequest, got %s\n", res.Status))
	}

	request.URL, _ = url.Parse("http://smth.com/v1/encrypt?zone_id=incorrect_zone")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, []byte(`incorrect client id`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf(fmt.Sprintf("Should not be able to encrypt with incorrect zone id -> Status code should be BadRequest, got %s\n", res.Status))
	}

	request.Body = ioutil.NopCloser(bytes.NewReader(data))
	keyStore.EncryptionKeypair.Public.Value = []byte("trash")
	request.URL, _ = url.Parse("http://smth.com/v1/encrypt")
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf(fmt.Sprintf("Should not be able to encrypt with incorrect zone id -> Status code should be BadRequest, got %s\n", res.Status))
	}

}

func TestHTTPEncryptionAcraStruct(t *testing.T) {
	keyStore := &testKeystore{}
	logger := log.NewEntry(log.New())
	translatorData := &common.TranslatorData{Keystorage: keyStore, CheckPoisonRecords: false}
	httpConnectionsDecryptor, err := NewHTTPConnectionsDecryptor(translatorData)
	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.EncryptionKeypair = keypair

	clientID := []byte("some client id")
	data := []byte("some data")
	request := http.Request{Method: http.MethodPost}

	// check with clientID
	request.Body = ioutil.NopCloser(bytes.NewReader(data))
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/encrypt?client_id=%s", clientID))
	res := httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf(fmt.Sprintf("Expects status OK, got %s\n", res.Status))
	}
	encryptedAcraStruct, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := base.DecryptAcrastruct(encryptedAcraStruct, keypair.Private, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("Incorrect response body")
	}

	// test with zone
	zoneID := []byte("some zone")
	// check with clientID
	request.Body = ioutil.NopCloser(bytes.NewReader(data))
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/encrypt?zone_id=%s", zoneID))
	res = httpConnectionsDecryptor.ParseRequestPrepareResponse(logger, &request, clientID)
	if res.StatusCode != http.StatusOK {
		t.Fatalf(fmt.Sprintf("Expects status OK, got %s\n", res.Status))
	}
	encryptedAcraStruct, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = base.DecryptAcrastruct(encryptedAcraStruct, keypair.Private, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("Incorrect response body")
	}
}
