package http_api

import (
	"bytes"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"fmt"
	"io"
	"net/http"
	"strings"
	"os"
	"github.com/cossacklabs/acra/keystore"
	"net"
	"io/ioutil"
	"github.com/cossacklabs/acra/decryptor/base"
)

type HTTPConnectionsDecryptor struct {
	keystorage keystore.KeyStore
}

func NewHTTPConnectionsDecryptor(keystorage keystore.KeyStore) (*HTTPConnectionsDecryptor, error) {
	return &HTTPConnectionsDecryptor{keystorage: keystorage}, nil
}

func (decryptor *HTTPConnectionsDecryptor) SendResponseAndCloseConnection(logger *log.Entry, response *http.Response, connection net.Conn) {
	r, err := ioutil.ReadAll(response.Body)
	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()

	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReturnResponse).
			Warningln("Can't convert response to binary %s", response)
	} else {
		_, err = connection.Write(r)
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantReturnResponse).
				Warningln("Can't write response to HTTP request")
		}
	}

	//err = connection.Close()
	//if err != nil {
	//	logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantCloseConnection).
	//		Warningln("Can't close connection of HTTP request")
	//}
	//logger.Infoln("Closed connection")
}

func (decryptor *HTTPConnectionsDecryptor) ParseRequestPrepareResponse(logger *log.Entry, request *http.Request, clientId []byte) *http.Response {
	if request == nil || request.URL == nil {
		return emptyResponseWithStatus(request, http.StatusBadRequest)
	}

	log.Debugf("Incoming API request to %v", request.URL.Path)

	if request.Method != http.MethodPost {
		msg := fmt.Sprintf("HTTP method is not allowed, expected POST, got %s", request.Method)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMethodNotAllowed).Warningf(msg)
		return responseWithMessage(request, http.StatusMethodNotAllowed, msg)
	}

	// /v1/decrypt
	// /, v1, decrypt
	pathParts := strings.Split(request.URL.Path, string(os.PathSeparator))
	if len(pathParts) != 3 {
		msg := fmt.Sprintf("Malformed URL, expected /<version>/<endpoint>, got %s", request.URL.Path)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderMalformedURL).Warningf(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	version := pathParts[1] // v1
	if version != "v1" {
		msg := fmt.Sprintf("HTTP request version is not supported: expected v1, got %s", version)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderVersionNotSupported).
			Warningf(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	endpoint := pathParts[2] // decrypt

	switch endpoint {
	case "decrypt":
		var zoneId []byte = nil

		// optional zone_id
		query, ok := request.URL.Query()["zone_id"]
		if ok && len(query) == 1 {
			zoneId = []byte(query[0])
		}

		if zoneId == nil && clientId == nil {
			msg := fmt.Sprintf("HTTP request doesn't have a ZoneId, connection doesn't have a ClientId, expected to get one of them. Send ZoneId in request URL")
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantZoneIdMissing).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		if request.Body == nil {
			msg := fmt.Sprintf("HTTP request doesn't have a body, expected to get AcraStruct")
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		acraStruct, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()

		if acraStruct == nil || err != nil {
			msg := fmt.Sprintf("Can't parse body from HTTP request, expected to get AcraStruct")
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		decryptedStruct, err := decryptor.decryptAcraStruct(acraStruct, zoneId, clientId)

		if err != nil {
			msg := fmt.Sprintf("Can't decrypt AcraStruct")
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderCantDecryptAcraStruct).Warningln(msg)
			return responseWithMessage(request, http.StatusUnprocessableEntity, msg)
		}

		logger.Infof("Decrypted AcraStruct for client_id=%s zone_id=%s", clientId, zoneId)

		response := emptyResponseWithStatus(request, http.StatusOK)
		response.Header.Set("Content-Type", "application/octet-stream")
		response.Body = ioutil.NopCloser(bytes.NewReader(decryptedStruct))
		response.ContentLength = int64(len(decryptedStruct))
		return response
	default:
		msg := "HTTP endpoint not supported"
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderEndpointNotSupported).
			Warningln(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	msg := "Unexpected parsing end during HTTP request parsing"
	logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorReaderEndpointNotSupported).
		Warningln(msg)
	return responseWithMessage(request, http.StatusBadRequest, msg)
}

func (decryptor *HTTPConnectionsDecryptor) decryptAcraStruct(acraStruct []byte, zoneId []byte, clientId []byte) ([]byte, error) {
	var err error
	var privateKey *keys.PrivateKey
	var decryptionContext []byte = nil

	if len(zoneId) != 0 {
		privateKey, err = decryptor.keystorage.GetZonePrivateKey(zoneId)
		decryptionContext = zoneId
	} else {
		privateKey, err = decryptor.keystorage.GetServerDecryptionPrivateKey(clientId)
	}

	if err != nil {
		return nil, err
	}

	// decrypt
	decryptedStruct, err := base.DecryptAcrastruct(acraStruct, privateKey, decryptionContext)
	// zeroing private key
	utils.FillSlice(byte(0), privateKey.Value)

	if err != nil {
		return nil, err
	}

	return decryptedStruct, nil
}

func emptyResponseWithStatus(request *http.Request, status int) *http.Response {
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       request,
		ContentLength: -1,
		Header:        http.Header{},
	}
}

func responseWithMessage(request *http.Request, status int, body string) *http.Response {
	response := emptyResponseWithStatus(request, status)
	response.Header.Set("Content-Type", "text/plain")
	response.Body = ioutil.NopCloser(bytes.NewReader([]byte(body)))
	response.ContentLength = int64(len([]byte(body)))
	return response
}

func (decryptor *HTTPConnectionsDecryptor) EmptyResponseWithStatus(request *http.Request, status int) *http.Response {
	return emptyResponseWithStatus(request, status)
}
