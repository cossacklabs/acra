package http_api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	pseudonymizationCommon "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gin-gonic/gin/render"
	log "github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// HTTPError store HTTP response status and message
type HTTPError struct {
	Code    int    `json:"code" example:"400"`
	Message string `json:"message" example:"invalid request body"`
}

// Empty return true if Code and Message equal to init values
func (err HTTPError) Empty() bool {
	return err.Code == 0 && err.Message == ""
}

// NewHTTPError return new initialized HTTPError
func NewHTTPError(status int, message string) HTTPError {
	return HTTPError{status, message}
}

// RespondWithError encode error to proper response format and write to client using ctx
func RespondWithError(ctx *gin.Context, err HTTPError) {
	switch ctx.ContentType() {
	case gin.MIMEJSON:
		ctx.JSON(err.Code, err)
	case gin.MIMEXML:
		ctx.XML(err.Code, err)
	default:
		log.WithField("content_type", ctx.ContentType()).Errorln("Unsupported content type for error response")
		ctx.String(err.Code, err.Message)
	}
}

// binaryType marshal byte arrays as base64 strings for JSON output and Unmarshal base64 strings back
type binaryType []byte

// UnmarshalJSON decode json string literal as base64 string to byte slice
func (data *binaryType) UnmarshalJSON(bytes []byte) (err error) {
	err = &json.InvalidUnmarshalError{Type: reflect.TypeOf(data)}
	if len(bytes) < 2 {
		return
	}
	// should be a string literal ""
	if bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return
	}
	if len(bytes) == 2 {
		*data = []byte{}
		return nil
	}
	size := base64.StdEncoding.DecodedLen(len(bytes) - 1)
	*data = make([]byte, size)
	n, err := base64.StdEncoding.Decode(*data, bytes[1:len(bytes)-1])
	*data = (*data)[:n]
	return nil
}

// MarshalJSON encode byte slice to base64 encoded string literal
func (data *binaryType) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(*data))
}

type zoneIDType []byte

// UnmarshalJSON string value of zoneID as []byte golang value
func (data *zoneIDType) UnmarshalJSON(bytes []byte) (err error) {
	err = &json.InvalidUnmarshalError{Type: reflect.TypeOf(data)}
	if len(bytes) < 2 {
		return
	}
	// should be a string literal ""
	if bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return
	}
	if len(bytes) == 2 {
		*data = []byte{}
		return nil
	}
	bytes = bytes[1 : len(bytes)-1]
	*data = make([]byte, len(bytes))
	copy(*data, bytes)
	return nil
}

func bindData(obj interface{}, data []byte, ctx *gin.Context) error {
	// support only xml
	switch ctx.ContentType() {
	case gin.MIMEXML, gin.MIMEXML2:
	case gin.MIMEJSON:
		break
	default:
		return errors.New("unsupported data content-type")
	}
	// pass POST method to avoid skipping inside Default function for other methods
	dataBinding := binding.Default(http.MethodPost, ctx.ContentType())
	bodyBinding, ok := dataBinding.(binding.BindingBody)
	if !ok {
		return errors.New("unsupported binding for specified Content-Type")
	}
	return bodyBinding.BindBody(data, obj)
}

// encryptionHTTPRequest used to map json/xml/form data from HTTP requests
type encryptionHTTPRequest struct {
	ZoneID zoneIDType `json:"zone_id" example:"DDDDDDDDMatNOMYjqVOuhACC"`
	Data   binaryType `json:"data" swaggertype:"string" format:"base64" example:"ZGF0YQo="`
}

type encryptionHTTPResponse struct {
	Data binaryType `swaggertype:"string" format:"base64" json:"data" example:"ZGF0YQo="`
}

// HTTPService implements HTTP API v1 and REST API v2 using ITranslatorService as logic backend
type HTTPService struct {
	engine         *gin.Engine
	translatorData *common.TranslatorData
	service        common.ITranslatorService
	server         *http.Server
	ctx            context.Context
}

// ServiceOption to configure HTTPService
type ServiceOption func(service *HTTPService)

// WithContext return option that configures HTTPService with specified context
func WithContext(ctx context.Context) ServiceOption {
	return func(service *HTTPService) {
		service.ctx = ctx
	}
}

// WithConnectionContextHandler return new option that registers http.Server.ConnContext handler for http.Server
func WithConnectionContextHandler(handler func(ctx context.Context, c net.Conn) context.Context) ServiceOption {
	return func(service *HTTPService) {
		service.server.ConnContext = handler
	}
}

// NewHTTPService return new initialized http service that ready to process new connections
func NewHTTPService(service common.ITranslatorService, translatorData *common.TranslatorData, options ...ServiceOption) (*HTTPService, error) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.Default()
	engine.HandleMethodNotAllowed = true
	// wrap service with metrics that track time of execution
	serviceWithMetrics, err := common.NewPrometheusServiceWrapper(service, common.HTTPRequestType)
	if err != nil {
		return nil, err
	}
	newHTTPService := &HTTPService{
		service:        serviceWithMetrics,
		engine:         engine,
		ctx:            context.Background(),
		translatorData: translatorData,
	}
	v1 := engine.Group("/v1")
	{
		v1.POST("/decrypt", newHTTPService.decryptOld)
		v1.POST("/encrypt", newHTTPService.encryptOld)
	}
	v2 := engine.Group("/v2")
	{
		// OLD with GET method
		// AcraStructs
		v2.GET("/decrypt", newHTTPService.decrypt)
		v2.GET("/encrypt", newHTTPService.encrypt)
		v2.GET("/encryptSearchable", newHTTPService.encryptSearchable)
		v2.GET("/decryptSearchable", newHTTPService.decryptSearchable)

		// AcraBlocks
		v2.GET("/decryptSym", newHTTPService.decryptSym)
		v2.GET("/encryptSym", newHTTPService.encryptSym)
		v2.GET("/encryptSymSearchable", newHTTPService.encryptSymSearchable)
		v2.GET("/decryptSymSearchable", newHTTPService.decryptSymSearchable)
		v2.GET("/generateQueryHash", newHTTPService.generateQueryHash)
		v2.GET("/tokenize", newHTTPService.tokenize)
		v2.GET("/detokenize", newHTTPService.detokenize)

		// new with POST method
		v2.POST("/decrypt", newHTTPService.decrypt)
		v2.POST("/encrypt", newHTTPService.encrypt)
		v2.POST("/encryptSearchable", newHTTPService.encryptSearchable)
		v2.POST("/decryptSearchable", newHTTPService.decryptSearchable)

		// AcraBlocks
		v2.POST("/decryptSym", newHTTPService.decryptSym)
		v2.POST("/encryptSym", newHTTPService.encryptSym)
		v2.POST("/encryptSymSearchable", newHTTPService.encryptSymSearchable)
		v2.POST("/decryptSymSearchable", newHTTPService.decryptSymSearchable)
		v2.POST("/generateQueryHash", newHTTPService.generateQueryHash)
		v2.POST("/tokenize", newHTTPService.tokenize)
		v2.POST("/detokenize", newHTTPService.detokenize)

		var confs []func(config *ginSwagger.Config)
		if url, ok := os.LookupEnv("ACRA_TRANSLATOR_SWAGGER_SCHEMA_URL"); ok {
			// The url pointing to API definition for swagger UI (http://localhost:9494/v2/swagger/doc.json)
			confs = append(confs, ginSwagger.URL(url))
		}

		// export json for swagger
		v2.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, confs...))
	}
	OnHTTPServerInit(newHTTPService.ctx, engine, translatorData, newHTTPService)

	server := &http.Server{
		Handler:      engine,
		ReadTimeout:  network.DefaultNetworkTimeout,
		WriteTimeout: network.DefaultNetworkTimeout,
	}
	newHTTPService.server = server
	for _, option := range options {
		option(newHTTPService)
	}
	return newHTTPService, nil
}

type operationFunc func(*gin.Context, []byte) (interface{}, HTTPError)

func convertEncryptionFuncToOperation(f func(*gin.Context, []byte) (encryptionHTTPResponse, HTTPError)) operationFunc {
	return func(ctx *gin.Context, data []byte) (interface{}, HTTPError) {
		return f(ctx, data)
	}
}

func convertTokenizationFuncToOperation(f func(*gin.Context, []byte) (tokenizationHTTPResponse, HTTPError)) operationFunc {
	return func(ctx *gin.Context, data []byte) (interface{}, HTTPError) {
		return f(ctx, data)
	}
}

const (
	encryptOperation           = "encrypt"
	decryptOperation           = "decrypt"
	encryptSearchableOperation = "encryptSearchable"
	decryptSearchableOperation = "decryptSearchable"

	encryptSymOperation           = "encryptSym"
	decryptSymOperation           = "decryptSym"
	encryptSymSearchableOperation = "encryptSymSearchable"
	decryptSymSearchableOperation = "decryptSymSearchable"

	generateQueryHashOperation = "generateQueryHash"

	tokenizeOperation   = "tokenize"
	detokenizeOperation = "detokenize"
)

func (service *HTTPService) operationToFunc(operation string) (operationFunc, error) {
	switch operation {
	case encryptOperation:
		return convertEncryptionFuncToOperation(service._encrypt), nil
	case decryptOperation:
		return convertEncryptionFuncToOperation(service._decrypt), nil
	case encryptSearchableOperation:
		return convertEncryptionFuncToOperation(service._encryptSearchable), nil
	case decryptSearchableOperation:
		return convertEncryptionFuncToOperation(service._decryptSearchable), nil
	case encryptSymOperation:
		return convertEncryptionFuncToOperation(service._encryptSym), nil
	case decryptSymOperation:
		return convertEncryptionFuncToOperation(service._decryptSym), nil
	case encryptSymSearchableOperation:
		return convertEncryptionFuncToOperation(service._encryptSymSearchable), nil
	case decryptSymSearchableOperation:
		return convertEncryptionFuncToOperation(service._decryptSymSearchable), nil
	case generateQueryHashOperation:
		return convertEncryptionFuncToOperation(service._generateQueryHash), nil
	case tokenizeOperation:
		return convertTokenizationFuncToOperation(service._tokenize), nil
	case detokenizeOperation:
		return convertTokenizationFuncToOperation(service._detokenize), nil
	}
	return nil, errors.New("unsupported operation type")
}

// Start http server that process new HTTP connections through listener
func (service *HTTPService) Start(listener net.Listener) error {
	go func() {
		<-service.ctx.Done()
		ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(network.DefaultNetworkTimeout))
		if err := service.server.Shutdown(ctx); err != nil {
			log.WithError(err).Errorln("Can't shutdown HTTP server")
			if closeErr := service.server.Close(); err != nil {
				log.WithError(closeErr).Errorln("Can't close HTTP server")
			}
		}
	}()
	return service.server.Serve(listener)
}

func (service *HTTPService) decryptOld(ctx *gin.Context) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context())
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	zoneID := []byte(ctx.Query("zone_id"))
	if ctx.Request.Body == nil {
		msg := fmt.Sprintf("HTTP request doesn't have a body, expected to get AcraStruct")
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
		ctx.String(http.StatusBadRequest, msg)
		return
	}
	acraStruct, err := ctx.GetRawData()
	if err != nil {
		msg := fmt.Sprintf("Can't parse body from HTTP request, expected to get AcraStruct")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
		ctx.String(http.StatusBadRequest, msg)
		return
	}
	decryptedStruct, err := service.service.Decrypt(service.ctx, acraStruct, connectionClientID, zoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't decrypt AcraStruct")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
		ctx.String(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	logger.Infoln("Decrypted AcraStruct")
	ctx.Render(http.StatusOK, render.Data{Data: decryptedStruct, ContentType: "application/octet-stream"})
	return
}

func (service *HTTPService) encryptOld(ctx *gin.Context) {
	log.Debugln("Process HTTP request to encrypt data")
	logger := logging.GetLoggerFromContext(ctx.Request.Context())
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	zoneID := []byte(ctx.Query("zone_id"))
	if ctx.Request.Body == nil {
		msg := fmt.Sprintf("HTTP request doesn't have a body, expected to get data")
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
		ctx.String(http.StatusBadRequest, msg)
		return
	}
	plaintext, err := ctx.GetRawData()
	if err != nil {
		msg := fmt.Sprintf("Can't parse body from HTTP request, expected to get data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantParseRequestBody).Warningln(msg)
		ctx.String(http.StatusBadRequest, msg)
		return
	}
	decryptedStruct, err := service.service.Encrypt(service.ctx, plaintext, connectionClientID, zoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't encrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
		ctx.String(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	ctx.Render(http.StatusOK, render.Data{Data: decryptedStruct, ContentType: "application/octet-stream"})
	return
}

// callOperationImplementation read body payload, pass it to implementation and render response
func callOperationImplementation(ctx *gin.Context, f func(*gin.Context, []byte) (interface{}, HTTPError)) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context())
	if ctx.Request.Method == http.MethodGet {
		logger.Warningln("Deprecated HTTP GET method was used. Please use HTTP POST method instead.")
	}
	data, err := ctx.GetRawData()
	if err != nil {
		logger.WithError(err).Errorln("Can't read body payload")
		RespondWithError(ctx, NewHTTPError(http.StatusBadRequest, "invalid request body"))
		return
	}
	defer ctx.Request.Body.Close()
	response, httpErr := f(ctx, data)
	if !httpErr.Empty() {
		RespondWithError(ctx, httpErr)
		return
	}
	renderResponse(response, ctx, logger)
}

// encrypt godoc
// @Summary Encrypt with AcraStruct
// @Description Encrypt data with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/encrypt [get]
func (service *HTTPService) encrypt(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._encrypt))
}

func (service *HTTPService) _encrypt(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "encrypt")
	logger.Debugln("Process HTTP request to encrypt data")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	encryptedData, err := service.service.Encrypt(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't encrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantEncryptData).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	response = encryptionHTTPResponse{Data: encryptedData}
	return
}

// decrypt godoc
// @Summary Decrypt AcraStruct
// @Description Decrypt AcraStruct with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/decrypt [get]
func (service *HTTPService) decrypt(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._decrypt))
}

func (service *HTTPService) _decrypt(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "decrypt")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	decryptedData, err := service.service.Decrypt(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't decrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	response = encryptionHTTPResponse{Data: decryptedData}
	return
}

// encryptSearchable godoc
// @Summary Encrypt with searchable AcraStruct
// @Description Encrypt data with searchable AcraStruct with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/encryptSearchable [get]
func (service *HTTPService) encryptSearchable(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._encryptSearchable))
}
func (service *HTTPService) _encryptSearchable(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "encryptSearchable")
	logger.Debugln("Process HTTP request to encrypt searchable data")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if len(request.Data) <= 0 {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}

	encryptedData, err := service.service.EncryptSearchable(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't encrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	response = encryptionHTTPResponse{Data: append(encryptedData.Hash, encryptedData.EncryptedData...)}
	return
}

// decryptSearchable godoc
// @Summary Decrypt searchable AcraStruct
// @Description Decrypt searchable AcraStruct with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/decryptSearchable [get]
func (service *HTTPService) decryptSearchable(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._decryptSearchable))
}
func (service *HTTPService) _decryptSearchable(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "decryptSearchable")
	logger.Debugln("Process HTTP request to decrypt searchable AcraStruct")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	hash := hmac.ExtractHash(request.Data)
	hashData := hash.Marshal()
	acraStruct := request.Data[len(hashData):]
	decryptedData, err := service.service.DecryptSearchable(service.ctx, acraStruct, hashData, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't decrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	logger.Infoln("Decrypted data")
	response = encryptionHTTPResponse{Data: decryptedData}
	return
}

// generateQueryHash godoc
// @Summary Generates hash
// @Description generates hash for data that may be used as blind index
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/generateQueryHash [get]
func (service *HTTPService) generateQueryHash(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._generateQueryHash))
}
func (service *HTTPService) _generateQueryHash(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "generateQueryHash")
	logger.Debugln("Process HTTP request to encrypt searchable data")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if len(request.Data) <= 0 {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}

	newHash, err := service.service.GenerateQueryHash(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		// TODO lagovas(2021-06-24) add and use proper metric
		//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't calculate hash")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	// TODO lagovas(2021-06-24) add and use proper metric
	//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Calculated hash")
	response = encryptionHTTPResponse{Data: newHash}
	return
}

// encryptSymSearchable godoc
// @Summary Encrypt with searchable AcraBlock
// @Description Encrypt data with searchable AcraBlock with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/encryptSymSearchable [get]
func (service *HTTPService) encryptSymSearchable(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._encryptSymSearchable))
}
func (service *HTTPService) _encryptSymSearchable(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "encryptSymSearchable")
	logger.Debugln("Process HTTP request to encrypt searchable data with AcraBlock")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if len(request.Data) <= 0 {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}

	encryptedData, err := service.service.EncryptSymSearchable(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't encrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	response = encryptionHTTPResponse{Data: append(encryptedData.Hash, encryptedData.EncryptedData...)}
	return
}

// decryptSymSearchable godoc
// @Summary Decrypt searchable AcraBlock
// @Description Decrypt searchable AcraBlock with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/decryptSymSearchable [get]
func (service *HTTPService) decryptSymSearchable(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._decryptSymSearchable))
}
func (service *HTTPService) _decryptSymSearchable(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "decryptSymSearchable")
	logger.Debugln("Process HTTP request to decrypt searchable AcraBlock")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	hash := hmac.ExtractHash(request.Data)
	if hash == nil {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Invalid hash")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	hashData := hash.Marshal()
	acraStruct := request.Data[len(hashData):]
	decryptedData, err := service.service.DecryptSymSearchable(service.ctx, acraStruct, hashData, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't decrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	logger.Infoln("Decrypted data")
	response = encryptionHTTPResponse{Data: decryptedData}
	return
}

// encryptSym godoc
// @Summary Encrypt with AcraBlock
// @Description Encrypt data with AcraBlock with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/encryptSym [get]
func (service *HTTPService) encryptSym(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._encryptSym))
}
func (service *HTTPService) _encryptSym(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "encryptSym")
	logger.Debugln("Process HTTP request to encrypt with AcraBlock")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if len(request.Data) <= 0 {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}

	encryptedData, err := service.service.EncryptSym(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't encrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data")
	response = encryptionHTTPResponse{Data: encryptedData}
	return
}

// decryptSym godoc
// @Summary Decrypt AcraBlock
// @Description Decrypt AcraBlock with specified ZoneID or ClientID from connection
// @Accept  json
// @Produce  json
// @Param data body string true "Binary data encoded as Base64 string"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.encryptionHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/decryptSym [get]
func (service *HTTPService) decryptSym(ctx *gin.Context) {
	callOperationImplementation(ctx, convertEncryptionFuncToOperation(service._decryptSym))
}
func (service *HTTPService) _decryptSym(ctx *gin.Context, data []byte) (response encryptionHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "decryptSym")
	logger.Debugln("Process HTTP request to decrypt searchable AcraBlock")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := encryptionHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	decryptedData, err := service.service.DecryptSym(service.ctx, request.Data, connectionClientID, request.ZoneID)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't decrypt data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	logger.Infoln("Decrypted data")
	response = encryptionHTTPResponse{Data: decryptedData}
	return
}

// encryptionHTTPRequest used to map json/xml/form data from HTTP requests
type tokenizationHTTPRequest struct {
	ZoneID zoneIDType                       `json:"zone_id" example:"DDDDDDDDMatNOMYjqVOuhACC"`
	Data   json.RawMessage                  `json:"data" swaggertype:"string,integer" example:"ZGF0YQo="`
	Type   pseudonymizationCommon.TokenType `json:"type" example:"1"`
}

type tokenizationHTTPResponse struct {
	Data interface{} `json:"data" swaggertype:"string,integer"`
}

func prepareTokenizeResponse(obj interface{}, tokenType pseudonymizationCommon.TokenType) (tokenizationHTTPResponse, error) {
	// if it's []byte type then we should convert it to Base64 encoded string
	switch tokenType {
	case pseudonymizationCommon.TokenType_Bytes:
		bytesValue, ok := obj.([]byte)
		if !ok {
			return tokenizationHTTPResponse{}, pseudonymizationCommon.ErrUnknownTokenType
		}
		obj = base64.StdEncoding.EncodeToString(bytesValue)
	}
	return tokenizationHTTPResponse{Data: obj}, nil
}

func prepareDataToTokenization(data json.RawMessage, tokenType pseudonymizationCommon.TokenType) (interface{}, error) {
	switch tokenType {
	case pseudonymizationCommon.TokenType_Bytes:
		var strValue string
		if err := json.Unmarshal(data, &strValue); err != nil {
			return data, err
		}
		return base64.StdEncoding.DecodeString(strValue)
	case pseudonymizationCommon.TokenType_Email:
		var strValue string
		if err := json.Unmarshal(data, &strValue); err != nil {
			return data, err
		}
		return pseudonymizationCommon.Email(strValue), nil
	case pseudonymizationCommon.TokenType_String:
		var strValue string
		if err := json.Unmarshal(data, &strValue); err != nil {
			return data, err
		}
		return strValue, nil
	case pseudonymizationCommon.TokenType_Int32:
		var intValue int32
		if err := json.Unmarshal(data, &intValue); err != nil {
			return data, err
		}
		return intValue, nil
	case pseudonymizationCommon.TokenType_Int64:
		var intValue int64
		if err := json.Unmarshal(data, &intValue); err != nil {
			return data, err
		}
		return intValue, nil
	}
	return data, pseudonymizationCommon.ErrUnknownTokenType
}

// tokenize godoc
// @Summary Tokenize data
// @Description Tokenize data according to data type
// @Accept  json
// @Produce  json
// @Param data body string true "String or Base64 encoded binary value, or integer"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.tokenizationHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/tokenize [get]
func (service *HTTPService) tokenize(ctx *gin.Context) {
	callOperationImplementation(ctx, convertTokenizationFuncToOperation(service._tokenize))
}
func (service *HTTPService) _tokenize(ctx *gin.Context, data []byte) (response tokenizationHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "tokenize")
	logger.Debugln("Process HTTP request to tokenize data")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := tokenizationHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if request.Data == nil {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}
	dataToTokenize, err := prepareDataToTokenization(request.Data, request.Type)
	if err != nil {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't prepare data to tokenization")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	tokenizedData, err := service.service.Tokenize(service.ctx, dataToTokenize, request.Type, connectionClientID, request.ZoneID)
	if err != nil {
		// TODO lagovas(2021-06-24) add and use proper metric
		//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't tokenize data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	response, err = prepareTokenizeResponse(tokenizedData, request.Type)
	if err != nil {
		msg := fmt.Sprintf("Can't tokenize data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	// TODO lagovas(2021-06-24) add and use proper metric
	//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Tokenized data")
	return
}

// detokenize godoc
// @Summary Detokenize data
// @Description Detokenize data according to data type
// @Accept  json
// @Produce  json
// @Param data body string true "String or Base64 encoded binary value, or integer"
// @Param zone_id body string false "ZoneID"
// @Success 200 {object} http_api.tokenizationHTTPResponse
// @Failure 400 {object} http_api.HTTPError
// @Failure 422 {object} http_api.HTTPError
// @Router /v2/detokenize [get]
func (service *HTTPService) detokenize(ctx *gin.Context) {
	callOperationImplementation(ctx, convertTokenizationFuncToOperation(service._detokenize))
}
func (service *HTTPService) _detokenize(ctx *gin.Context, data []byte) (response tokenizationHTTPResponse, httpErr HTTPError) {
	logger := logging.GetLoggerFromContext(ctx.Request.Context()).WithField("operation", "detokenize")
	logger.Debugln("Process HTTP request to detokenize data")
	connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
	connectionClientID, ok := network.GetClientIDFromConnection(connection, service.translatorData.TLSClientIDExtractor)
	if !ok {
		connectionClientID = nil
	}
	request := tokenizationHTTPRequest{}
	if err := bindData(&request, data, ctx); err != nil {
		logger.WithError(err).WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}
	if request.Data == nil {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't bind data")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data, empty data")
		return
	}

	dataToDetokenize, err := prepareDataToTokenization(request.Data, request.Type)
	if err != nil {
		logger.WithField("content_type", ctx.ContentType()).Errorln("Can't prepare data to tokenization")
		httpErr = NewHTTPError(http.StatusBadRequest, "Invalid request data")
		return
	}

	detokenizedData, err := service.service.Detokenize(service.ctx, dataToDetokenize, request.Type, connectionClientID, request.ZoneID)
	if err != nil {
		// TODO lagovas(2021-06-24) add and use proper metric
		//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := fmt.Sprintf("Can't detokenize data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	if reflect.DeepEqual(dataToDetokenize, detokenizedData) {
		msg := fmt.Sprintf("Can't detokenize data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln("Can't find token")
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	response, err = prepareTokenizeResponse(detokenizedData, request.Type)
	if err != nil {
		msg := fmt.Sprintf("Can't tokenize data")
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantHandleHTTPRequest).Warningln(msg)
		httpErr = NewHTTPError(http.StatusUnprocessableEntity, msg)
		return
	}
	// TODO lagovas(2021-06-24) add and use proper metric
	//base.AcrastructDecryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Detokenized data")
	return
}

func renderResponse(obj interface{}, ctx *gin.Context, logger *log.Entry) {
	switch ctx.ContentType() {
	case gin.MIMEJSON:
		ctx.JSON(http.StatusOK, obj)
	case gin.MIMEXML:
		ctx.XML(http.StatusOK, obj)
	default:
		logger.WithField("content_type", ctx.ContentType()).Errorln("Unsupported response object")
		ctx.String(http.StatusInternalServerError, "Unsupported response type")
	}
}
