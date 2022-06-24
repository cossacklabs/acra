// Copyright 2022, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

const (
	errorRequestMessage = "incorrect request"
	// Key name for the logger in the gin.Context
	loggerKey = "logger"
)

// AcraAPIServer handles all HTTP api logic
type AcraAPIServer struct {
	ctx        context.Context
	api        APICore
	engine     *gin.Engine
	httpServer *http.Server
}

// APICore contains the API logic of the HTTP API server
// Is used to decouple the API logic from actual HTTP setting routine
// In the future could be used to abstract HTTP setting up from API configuring
type APICore struct {
	server *SServer
}

// NewAcraAPIServer creates new AcraAPIServer
func NewAcraAPIServer(ctx context.Context, server *SServer) AcraAPIServer {
	gin.SetMode(gin.ReleaseMode)
	api := NewAPICore(ctx, server)

	engine := gin.New()
	engine.
		Use(spanningMiddleware("HandleSession", server.config.TraceToLog, server.config.GetTraceOptions())).
		Use(loggerMiddleware(apiConnectionType)).
		// explicitly set writer to nil, so the stack frame is not printed
		Use(gin.CustomRecoveryWithWriter(nil, recoveryHandler()))

	engine.HandleMethodNotAllowed = true

	api.InitEngine(engine)

	apiServer := AcraAPIServer{
		ctx:        ctx,
		api:        api,
		engine:     engine,
		httpServer: nil,
	}

	httpServer := &http.Server{
		Handler:      engine,
		ReadTimeout:  network.DefaultNetworkTimeout,
		WriteTimeout: network.DefaultNetworkTimeout,
	}

	apiServer.httpServer = httpServer

	return apiServer
}

// Start the server. Blocking operation
func (apiServer *AcraAPIServer) Start(listener net.Listener) error {
	go func() {
		<-apiServer.ctx.Done()
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(network.DefaultNetworkTimeout))
		defer cancel()
		if err := apiServer.httpServer.Shutdown(ctx); err != nil {
			log.WithError(err).Errorln("Can't shutdown API server")
			if err := apiServer.httpServer.Close(); err != nil {
				log.WithError(err).Errorln("Can't close API server")
			}
		}
	}()
	return apiServer.httpServer.Serve(listener)
}

// NewAPICore creates new APICore
func NewAPICore(ctx context.Context, server *SServer) APICore {
	return APICore{server}
}

// InitEngine configures all path handlers for the API
func (api *APICore) InitEngine(engine *gin.Engine) {
	engine.GET("/getNewZone", api.getNewZoneGin)
	engine.GET("/resetKeyStorage", api.resetKeyStorageGin)
	engine.NoRoute(respondWithError)
}

func (api *APICore) getNewZone() (id []byte, publicKey []byte, err error) {
	keystore := api.server.config.GetKeyStore()
	id, publicKey, err = keystore.GenerateZoneKey()
	if err != nil {
		return nil, nil, err
	}
	if err = keystore.GenerateZoneIDSymmetricKey(id); err != nil {
		return nil, nil, err
	}
	return id, publicKey, nil
}

func (api *APICore) getNewZoneGin(ctx *gin.Context) {
	logger := ginGetLogger(ctx)

	id, pub, err := api.getNewZone()
	if err != nil {
		logger.WithError(err).
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorHTTPAPICantGenerateZone).
			Errorln("Can't generate zone key")

		respondWithError(ctx)
		return
	}
	zoneData, err := zone.DataToJSON(id, &keys.PublicKey{Value: pub})
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorHTTPAPICantGenerateZone).
			WithError(err).
			Errorln("Can't create json with zone key")
		respondWithError(ctx)
		return
	}
	ctx.Render(http.StatusOK, render.Data{
		ContentType: gin.MIMEJSON,
		Data:        zoneData,
	})
}

func (api *APICore) resetKeyStorage() {
	keystore := api.server.config.GetKeyStore()
	keystore.Reset()
}

func (api *APICore) resetKeyStorageGin(ctx *gin.Context) {
	logger := ginGetLogger(ctx)

	api.resetKeyStorage()
	logger.Debugln("Cleared key storage cache")
	ctx.String(http.StatusOK, "")
}

func respondWithError(ctx *gin.Context) {
	ctx.String(http.StatusNotFound, errorRequestMessage)
}

// loggerMiddleware returns the middleware that logs the request for debug purposes
func loggerMiddleware(connType string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Give each client session a unique ID (within an AcraServer instance).
		// This greatly simplifies tracking session activity across the logs.
		sessionID := atomic.AddUint32(&sessionCounter, 1)

		logger := logging.
			NewLoggerWithTrace(ctx.Request.Context()).
			WithFields(log.Fields{
				"session_id":        sessionID,
				connectionTypeLabel: connType,
			})

		ctx.Set(loggerKey, logger)

		logger.
			WithFields(log.Fields{
				"method": ctx.Request.Method,
				"path":   ctx.Request.URL.Path,
			}).
			Debugln("Incoming API request")
		// it will run all other middlewares and handlers
		// blocking until the request is done
		ctx.Next()

		logger.
			WithField("status_code", ctx.Writer.Status()).
			Debugln("Request is handled")
	}
}

func ginGetLogger(ctx *gin.Context) *log.Entry {
	logger, ok := ctx.Get(loggerKey)
	if ok {
		return logger.(*log.Entry)
	}
	panic("logger must be configured")
}

// recoveryHandler returns RecoveryFunc that logs the panic error and aborts
// the connection with 500 Internval Server Error
func recoveryHandler() gin.RecoveryFunc {
	return func(ctx *gin.Context, err interface{}) {
		logger := ginGetLogger(ctx)
		logger.
			WithField("error", err).
			WithField("connection_type", "http_api").
			Errorln("Panic in connection processing, close connection")

		ctx.AbortWithStatus(http.StatusInternalServerError)
	}
}

// spanningMiddleware returns new middleware that starts a span around the request
// processing
func spanningMiddleware(name string, traceToLog bool, options []trace.StartOption) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		newRequestCtx := logging.SetTraceStatus(ctx.Request.Context(), traceToLog)
		newRequestCtx, span := trace.StartSpan(newRequestCtx, name, options...)
		defer span.End()
		span.AddAttributes(trace.StringAttribute("method", ctx.Request.Method))
		span.AddAttributes(trace.StringAttribute("path", ctx.Request.URL.Path))
		ctx.Request = ctx.Request.WithContext(newRequestCtx)

		ctx.Next()
		statusCode := int64(ctx.Writer.Status())
		span.AddAttributes(trace.Int64Attribute("status_code", statusCode))
	}
}
