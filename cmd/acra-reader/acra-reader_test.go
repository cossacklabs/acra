package main

import (
	"testing"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"io/ioutil"
	"bytes"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/acra/acra-writer"
	"fmt"
)

func TestResponseStatus(t *testing.T) {
	keyStore := &testKeystore{}
	readerServer, err := NewReaderServer(nil, keyStore, 1)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	//logging.SetLogLevel(logging.LOG_DEBUG)
	logger := log.NewEntry(log.StandardLogger())

	res := readerServer.parseRequestPrepareResponse(logger, nil, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If no Request -> Status code should be Bad Request, got %s\n", res.Status)
	}

	request := http.Request{}
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If no Requets URL -> Status code should be Bad Request, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/weird")
	request.Method = http.MethodGet
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("If not POST -> Status code should be StatusMethodNotAllowed, got %s\n", res.Status)
	}

	request.Method = http.MethodPost
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If URL has no version -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1")
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If URL has no /decrypt endpoint -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If Request has no body -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.Body = ioutil.NopCloser(bytes.NewBufferString("bla bla bla body"))
	res = readerServer.parseRequestPrepareResponse(logger, &request, nil)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("If Request has no ZoneId and No ClientId -> Status code should be StatusBadRequest, got %s\n", res.Status)
	}

	request.URL, _ = url.Parse("http://smth.com/v1/decrypt?zone_id=\"somezoneid\"")
	request.Body = ioutil.NopCloser(bytes.NewBufferString("bla bla bla body"))
	res = readerServer.parseRequestPrepareResponse(logger, &request, []byte("asdf"))
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("If Request Bad ZoneId and ClientId -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status)
	}
}

func TestDecryptionAndResponse(t *testing.T) {
	keyStore := &testKeystore{}
	readerServer, err := NewReaderServer(nil, keyStore, 1)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	//logging.SetLogLevel(logging.LOG_DEBUG)
	logger := log.NewEntry(log.StandardLogger())


	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.PrivateKey = keypair.Private


	clientId := []byte("some client id")
	data := []byte("some data")

	// not an acrastruct
	request := http.Request{ Method : http.MethodPost }
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	request.Body = ioutil.NopCloser(bytes.NewBuffer([]byte("some garbage not acrastruct")))

	res := readerServer.parseRequestPrepareResponse(logger, &request, clientId)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("Should not be able to decrypt garbage -> Status code should be StatusUnprocessableEntity, got %s\n", res.Status)
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	request = http.Request{ Method : http.MethodPost }
	request.URL, _ = url.Parse("http://smth.com/v1/decrypt")
	request.Body = ioutil.NopCloser(bytes.NewBuffer(acrastruct))

	res = readerServer.parseRequestPrepareResponse(logger, &request, clientId)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Should be able to decrypt without zone -> Status code should be StatusOK, got %s\n", res.Status)
	}

	decryptedAcraStruct, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decryptedAcraStruct, data) {
		t.Fatal("Response data not equal to initial data")
	}

	// test with zone
	zoneId := clientId // use client id as zone id because no matter what to use
	acrastructWithZone, err := acrawriter.CreateAcrastruct(data, keypair.Public, zoneId)
	if err != nil {
		t.Fatal(err)
	}

	request = http.Request{ Method : http.MethodPost }
	request.URL, _ = url.Parse(fmt.Sprintf("http://smth.com/v1/decrypt?zone_id=%s", zoneId))
	request.Body = ioutil.NopCloser(bytes.NewBuffer(acrastructWithZone))

	res = readerServer.parseRequestPrepareResponse(logger, &request, clientId)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Should be able to decrypt with zone -> Status code should be StatusOK, got %s\n", res.Status)
	}

	decryptedAcraStructWithZone, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decryptedAcraStructWithZone, data) {
		t.Fatal("Response data not equal to initial data")
	}
}

func TestDecryptionAcraStruct(t *testing.T) {
	keyStore := &testKeystore{}
	readerServer, err := NewReaderServer(nil, keyStore, 1)

	if err != nil {
		t.Fatalf("Can't create ReaderServer. err = %v\n", err)
	}

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	keyStore.PrivateKey = keypair.Private


	clientId := []byte("some client id")
	data := []byte("some data")

	// not an acrastruct
	decrypted, err := readerServer.decryptAcraStruct([]byte("some garbage not acrastruct"), nil, clientId)
	if err == nil {
		t.Fatalf("Should not be able to decrypt garbage")
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = readerServer.decryptAcraStruct(acrastruct, nil, clientId)
	if err != nil {
		t.Fatalf("Should be able to decrypt acrastruct without zone")
	}

	if !bytes.Equal(decrypted, data) {
		t.Fatal("Decrypted acrastruct is not equal to initial data")
	}


	// test with zone
	zoneId := clientId // use client id as zone id because no matter what to use
	acrastructWithZone, err := acrawriter.CreateAcrastruct(data, keypair.Public, zoneId)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = readerServer.decryptAcraStruct(acrastructWithZone, zoneId, clientId)
	if err != nil {
		t.Fatalf("Should be able to decrypt acrastruct with zone")
	}

	if !bytes.Equal(decrypted, data) {
		t.Fatal("Decrypted acrastruct is not equal to initial data")
	}
}