package http_api

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
)

type HTTPConnectionsDecryptor struct {
	keystorage keystore.KeyStore
	poisonCallbacks *base.PoisonCallbackStorage
}

func NewHTTPConnectionsDecryptor(keystorage keystore.KeyStore, poisonRecordCallbacks *base.PoisonCallbackStorage) (*HTTPConnectionsDecryptor, error) {
	return &HTTPConnectionsDecryptor{keystorage: keystorage, poisonCallbacks: poisonRecordCallbacks}, nil
}

func (decryptor *HTTPConnectionsDecryptor) SendResponse(logger *log.Entry, response *http.Response, connection net.Conn) {
	outBuffer  := &bytes.Buffer{}
	err := response.Write(outBuffer)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantReturnResponse).
			Warningln("Can't write response to buffer")
	}
	_, err = outBuffer.WriteTo(connection)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantReturnResponse).
			Warningln("Can't write response to buffer")
	}
}

func (decryptor *HTTPConnectionsDecryptor) ParseRequestPrepareResponse(logger *log.Entry, request *http.Request, clientId []byte) *http.Response {
	if request == nil || request.URL == nil {
		return emptyResponseWithStatus(request, http.StatusBadRequest)
	}

	log.Debugf("Incoming API request to %v", request.URL.Path)

	if request.Method != http.MethodPost {
		msg := fmt.Sprintf("HTTP method is not allowed, expected POST, got %s", request.Method)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorMethodNotAllowed).Warningf(msg)
		return responseWithMessage(request, http.StatusMethodNotAllowed, msg)
	}

	// /v1/decrypt
	// /, v1, decrypt
	pathParts := strings.Split(request.URL.Path, string(os.PathSeparator))
	if len(pathParts) != 3 {
		msg := fmt.Sprintf("Malformed URL, expected /<version>/<endpoint>, got %s", request.URL.Path)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorMalformedURL).Warningf(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	version := pathParts[1] // v1
	if version != "v1" {
		msg := fmt.Sprintf("HTTP request version is not supported: expected v1, got %s", version)
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorVersionNotSupported).
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
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantZoneIdMissing).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		if request.Body == nil {
			msg := fmt.Sprintf("HTTP request doesn't have a body, expected to get AcraStruct")
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		acraStruct, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()

		if acraStruct == nil || err != nil {
			msg := fmt.Sprintf("Can't parse body from HTTP request, expected to get AcraStruct")
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		decryptedStruct, err := decryptor.decryptAcraStruct(logger, acraStruct, zoneId, clientId)

		if err != nil {
			msg := fmt.Sprintf("Can't decrypt AcraStruct")
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
			response := responseWithMessage(request, http.StatusUnprocessableEntity, msg)
			// check poison records
			poisoned, err := base.CheckPoisonRecord(acraStruct, decryptor.keystorage)
			if err != nil {
				logger.WithError(err).Errorln("Can't check is it poison record")
				return response
			}
			if poisoned {
				logger.Errorln("Recognized poison record")
				if decryptor.poisonCallbacks.HasCallbacks() {
					if err := decryptor.poisonCallbacks.Call(); err != nil {
						logger.WithError(err).Errorln("Unexpected error on poison record's callbacks")
					}
				}
				return response
			}
			return response
		}

		logger.Infof("Decrypted AcraStruct for client_id=%s zone_id=%s", clientId, zoneId)

		response := emptyResponseWithStatus(request, http.StatusOK)
		response.Header.Set("Content-Type", "application/octet-stream")
		response.Body = ioutil.NopCloser(bytes.NewReader(decryptedStruct))
		response.ContentLength = int64(len(decryptedStruct))
		return response
	default:
		msg := "HTTP endpoint not supported"
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorEndpointNotSupported).
			Warningln(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	msg := "Unexpected parsing end during HTTP request parsing"
	logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorEndpointNotSupported).
		Warningln(msg)
	return responseWithMessage(request, http.StatusBadRequest, msg)
}

func (decryptor *HTTPConnectionsDecryptor) decryptAcraStruct(logger *log.Entry, acraStruct []byte, zoneId []byte, clientId []byte) ([]byte, error) {
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
		logger.Errorln("Can't load private key to decrypt AcraStruct")
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
	response := &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       request,
		ContentLength: -1,
		Header:        http.Header{},
	}
	response.Header.Set("Connection", "close")
	return response
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
