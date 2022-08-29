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
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

const (
	errorRequestMessage = "incorrect request"
	// Key name for the logger in the gin.Context
	loggerKey = "logger"
	// Key name for the clientID saved in the gin.Context
	clientIDKey = "clientID"
)

// HTTPAPIServer handles all HTTP api logic
type HTTPAPIServer struct {
	ctx        context.Context
	api        APICore
	httpServer *http.Server
}

// APICore contains the API logic of the HTTP API server
// Is used to decouple the API logic from actual HTTP setting routine
// In the future could be used to abstract HTTP setting up from API configuring
type APICore struct {
	keystore keystore.ServerKeyStore
}

// ConnectionContextCallback is callback that is called to map context for
// each connection
// We use it to set the connection to the context, so it can be use latter (for
// extracting the clientID for example)
type ConnectionContextCallback func(ctx context.Context, c net.Conn) context.Context

// NewHTTPAPIServer creates new AcraAPIServer
// The arguments:
// - keystore is a keystore operated by the Acra
// - traceOn controls the tracing. Often provided from the config.
// - traceOptions - options for the tracer. Often provided from the config.
// - tlsIDExtractor is used to extract IDs from the TLS connection
// - connCtxCallback is a callback for setting context for each connection
func NewHTTPAPIServer(
	ctx context.Context,
	keystore keystore.ServerKeyStore,
	traceOn bool,
	traceOptions []trace.StartOption,
	tlsIDExtractor network.TLSClientIDExtractor,
	connCtxCallback ConnectionContextCallback,
) HTTPAPIServer {
	gin.SetMode(gin.ReleaseMode)
	api := NewAPICore(ctx, keystore)

	engine := gin.New()
	engine.
		Use(spanningMiddleware("HandleSession", traceOn, traceOptions)).
		Use(clientIDMiddleware(tlsIDExtractor)).
		Use(loggerMiddleware(apiConnectionType)).
		// explicitly set writer to nil, so the stack frame is not printed
		Use(gin.CustomRecoveryWithWriter(nil, recoveryHandler()))

	engine.HandleMethodNotAllowed = true

	apiServer := HTTPAPIServer{
		ctx:        ctx,
		api:        api,
		httpServer: nil,
	}

	apiServer.InitEngine(engine)

	httpServer := &http.Server{
		Handler:      engine,
		ReadTimeout:  network.DefaultNetworkTimeout,
		WriteTimeout: network.DefaultNetworkTimeout,
		ConnContext:  connCtxCallback,
		// Discard logs because there is no clear way of using logrus here
		ErrorLog: stdlog.New(ioutil.Discard, "", 0),
	}

	apiServer.httpServer = httpServer

	return apiServer
}

// Start the server. Blocking operation
func (apiServer *HTTPAPIServer) Start(listener net.Listener, group *sync.WaitGroup) error {
	group.Add(1)
	go func() {
		defer group.Done()
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
	err := apiServer.httpServer.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// NewAPICore creates new APICore
func NewAPICore(ctx context.Context, keystore keystore.ServerKeyStore) APICore {
	return APICore{keystore}
}

// InitEngine configures all path handlers for the API
func (apiServer *HTTPAPIServer) InitEngine(engine *gin.Engine) {
	engine.GET("/resetKeyStorage", apiServer.resetKeyStorageGin)
	engine.NoRoute(respondWithError)
}

func (api *APICore) resetKeyStorage() {
	api.keystore.Reset()
}

func (apiServer *HTTPAPIServer) resetKeyStorageGin(ctx *gin.Context) {
	logger := ginGetLogger(ctx)

	apiServer.api.resetKeyStorage()
	logger.Infoln("Cleared key storage cache")
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

		clientID := ginGetClientID(ctx)

		if clientID != nil {
			logger = logger.WithField("client_id", string(clientID))
		}
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
func spanningMiddleware(name string, traceOn bool, options []trace.StartOption) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		newRequestCtx := logging.SetTraceStatus(ctx.Request.Context(), traceOn)
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

// clientIDMiddleware extracts the clientID from the connection and saves it into
// the gin's context.
func clientIDMiddleware(tlsExtractor network.TLSClientIDExtractor) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// First check the context, as it has the highest priority, because it
		// can contain the static client ID even if TLS is used.
		clientID, ok := network.GetClientIDFromHTTPContext(ctx.Request.Context())
		if !ok {
			connection := network.GetConnectionFromHTTPContext(ctx.Request.Context())
			clientID, ok = network.GetClientIDFromConnection(connection, tlsExtractor)
		}
		if ok {
			ctx.Set(clientIDKey, clientID)
		}
	}
}

// ginGetClientID extracts the clientID from the gin's context. Returns nil if
// it's not setup.
func ginGetClientID(ctx *gin.Context) []byte {
	clientID, ok := ctx.Get(clientIDKey)
	if ok {
		return clientID.([]byte)
	}
	return nil
}

// BuildHTTPAPIConnectionWrapper builds the connection wrapper that will be used
// by the HTTP API server.
// If `tlsWrapper` is nil, no TLS protection is used and connections will use
// the specified clientID.
// If clientIDFromCert is true, the clientID will be derived from the TLS user
// certificate. If false, the static clientID will be used.
func BuildHTTPAPIConnectionWrapper(tlsWrapper *network.TLSConnectionWrapper, clientIDFromCert bool, clientID []byte) (network.HTTPServerConnectionWrapper, error) {
	httpWrapper, err := network.NewHTTPServerConnectionWrapper()
	if err != nil {
		return nil, err
	}
	httpWrapper.AddCallback(NewMetricConnectionCallback(apiConnectionType))
	httpWrapper.AddConnectionContextCallback(network.ConnectionToContextCallback{})
	httpWrapper.AddCallback(network.SafeCloseConnectionCallback{})
	if tlsWrapper == nil {
		// Save static clientID into the context. Otherwise, it will be derived
		// from the TLS connection.
		httpWrapper.AddConnectionContextCallback(network.ClientIDToContextCallback{
			ClientID: clientID,
		})
	} else {
		// we should register transport callback last because http2 server
		// require that it should receive *tls.Conn object and we need to wrap
		// source connection with our wrappers before switching to TLS
		httpWrapper.AddCallback(tlsWrapper)
		if !clientIDFromCert {
			httpWrapper.AddConnectionContextCallback(network.ClientIDToContextCallback{
				ClientID: clientID,
			})
		}
	}

	return httpWrapper, nil
}
