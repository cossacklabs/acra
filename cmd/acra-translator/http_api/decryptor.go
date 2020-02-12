/*
Copyright 2018, Cossack Labs Limited

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

// Package http_api implements HTTP API handler: users can send AcraStructs via HTTP to AcraConnector,
// AcraConnector wraps connection via Themis SecureSession. HTTP handler parses HTTP requests, decrypts AcraStructs
// and returns plaintext data via HTTP response.
package http_api

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
)

// HTTPConnectionsDecryptor object for decrypting AcraStructs from HTTP requests.
type HTTPConnectionsDecryptor struct {
	*common.TranslatorData
}

// NewHTTPConnectionsDecryptor creates HTTPConnectionsDecryptor object.
func NewHTTPConnectionsDecryptor(data *common.TranslatorData) (*HTTPConnectionsDecryptor, error) {
	return &HTTPConnectionsDecryptor{TranslatorData: data}, nil
}

// SendResponse sends HTTP response to connection using Buffer.
func (decryptor *HTTPConnectionsDecryptor) SendResponse(logger *log.Entry, response *http.Response, connection net.Conn) {
	outBuffer := &bytes.Buffer{}
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

// ParseRequestPrepareResponse parses HTTP request to find AcraStruct and ZoneID, then decrypts AcraStruct.
// Returns HTTP response with appropriate status code, headers, decrypted AcraStruct or error message.
func (decryptor *HTTPConnectionsDecryptor) ParseRequestPrepareResponse(logger *log.Entry, request *http.Request, clientID []byte) *http.Response {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(common.RequestProcessingTimeHistogram.WithLabelValues(common.HTTPRequestType).Observe))
	defer timer.ObserveDuration()

	requestLogger := logger.WithFields(log.Fields{"client_id": string(clientID), "translator": "http"})
	if request == nil || request.URL == nil {
		return emptyResponseWithStatus(request, http.StatusBadRequest)
	}

	requestLogger.Debugf("Incoming API request to %v", request.URL.Path)

	if request.Method != http.MethodPost {
		msg := fmt.Sprintf("HTTP method is not allowed, expected POST, got %s", request.Method)
		requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorMethodNotAllowed).Warningf(msg)
		return responseWithMessage(request, http.StatusMethodNotAllowed, msg)
	}

	// /v1/decrypt
	// /, v1, decrypt
	pathParts := strings.Split(request.URL.Path, string(os.PathSeparator))
	if len(pathParts) != 3 {
		msg := fmt.Sprintf("Malformed URL, expected /<version>/<endpoint>, got %s", request.URL.Path)
		requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorMalformedURL).Warningf(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	version := pathParts[1] // v1
	if version != "v1" {
		msg := fmt.Sprintf("HTTP request version is not supported: expected v1, got %s", version)
		requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorVersionNotSupported).
			Warningf(msg)
		return responseWithMessage(request, http.StatusBadRequest, msg)
	}

	endpoint := pathParts[2] // decrypt

	switch endpoint {
	case "decrypt":
		var zoneID []byte

		// optional zone_id
		query, ok := request.URL.Query()["zone_id"]
		if ok && len(query) == 1 {
			zoneID = []byte(query[0])
			requestLogger = requestLogger.WithField("zone_id", query[0])
		}

		if zoneID == nil && clientID == nil {
			msg := fmt.Sprintf("HTTP request doesn't have a ZoneID, connection doesn't have a ClientID, expected to get one of them. Send ZoneID in request URL")
			requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDMissing).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		if request.Body == nil {
			msg := fmt.Sprintf("HTTP request doesn't have a body, expected to get AcraStruct")
			requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		acraStruct, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()

		if acraStruct == nil || err != nil {
			msg := fmt.Sprintf("Can't parse body from HTTP request, expected to get AcraStruct")
			requestLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
			return responseWithMessage(request, http.StatusBadRequest, msg)
		}

		decryptedStruct, err := decryptor.decryptAcraStruct(logger, acraStruct, zoneID, clientID)

		if err != nil {
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			msg := fmt.Sprintf("Can't decrypt AcraStruct")
			requestLogger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
			response := responseWithMessage(request, http.StatusUnprocessableEntity, msg)
			if decryptor.TranslatorData.CheckPoisonRecords {
				// check poison records
				poisoned, err := base.CheckPoisonRecord(acraStruct, decryptor.TranslatorData.Keystorage)
				if err != nil {
					requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record, possible missing Poison record decryption key")
					return response
				}
				if poisoned {
					requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Errorln("Recognized poison record")
					if decryptor.TranslatorData.PoisonRecordCallbacks.HasCallbacks() {
						if err := decryptor.TranslatorData.PoisonRecordCallbacks.Call(); err != nil {
							requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantHandleRecognizedPoisonRecord).WithError(err).Errorln("Unexpected error on poison record's callbacks")
						}
					}
					return response
				}
			}
			return response
		}
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
		requestLogger.Infoln("Decrypted AcraStruct")

		response := emptyResponseWithStatus(request, http.StatusOK)
		response.Header.Set("Content-Type", "application/octet-stream")
		response.Body = ioutil.NopCloser(bytes.NewReader(decryptedStruct))
		response.ContentLength = int64(len(decryptedStruct))
		return response
	}
	msg := "HTTP endpoint not supported"
	requestLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorEndpointNotSupported).
		Warningln(msg)
	return responseWithMessage(request, http.StatusBadRequest, msg)
}

func (decryptor *HTTPConnectionsDecryptor) decryptAcraStruct(logger *log.Entry, acraStruct []byte, zoneID []byte, clientID []byte) ([]byte, error) {
	var err error
	var privateKeys []*keys.PrivateKey
	var decryptionContext []byte

	if len(zoneID) != 0 {
		privateKeys, err = decryptor.TranslatorData.Keystorage.GetZonePrivateKeys(zoneID)
		decryptionContext = zoneID
	} else {
		privateKeys, err = decryptor.TranslatorData.Keystorage.GetServerDecryptionPrivateKeys(clientID)
	}

	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).Errorln("Can't load private key to decrypt AcraStruct")
		return nil, err
	}

	// decrypt
	decryptedStruct, err := base.DecryptRotatedAcrastruct(acraStruct, privateKeys, decryptionContext)
	// zeroing private keys
	for _, privateKey := range privateKeys {
		utils.FillSlice(byte(0), privateKey.Value)
	}

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

// EmptyResponseWithStatus creates HTTP response without body, with status code.
func (decryptor *HTTPConnectionsDecryptor) EmptyResponseWithStatus(request *http.Request, status int) *http.Response {
	return emptyResponseWithStatus(request, status)
}
