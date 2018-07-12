package main

import (
	"testing"
	"time"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"io/ioutil"
	"bytes"
	"github.com/cossacklabs/acra/keystore"
)

func TestResponseStatus(t *testing.T) {
	keyStore, err := keystore.NewFilesystemKeyStore("dir", nil)
	waitTimeout := time.Duration(1) * time.Second
	readerServer, err := NewReaderServer(nil, keyStore, waitTimeout)

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