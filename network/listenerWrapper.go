package network

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

// ErrListenerNotSet used if net.Listener wasn't set to HTTPServerConnectionWrapper
var ErrListenerNotSet = errors.New("listener not set to HTTPServerConnectionWrapper")

// HTTPServerConnectionWrapper implements net.Listener interface and allow to
type HTTPServerConnectionWrapper interface {
	net.Listener
	SetListener(net.Listener)
	AddCallback(callback ConnectionCallback)
	AddConnectionContextCallback(callback ConnectionContextCallback)
	OnConnectionContext(ctx context.Context, c net.Conn) context.Context
}

// ListenerWrapper interface allows to access wrapped listener by another listener implementation
type ListenerWrapper interface {
	Unwrap() net.Listener
}

// HTTPServerConnectionChainWrapper wraps net.Listener and allow to register callbacks that will be called on every new connection after listener.Accept
// and implements http.Server.ConnContext handler signature and allow register callbacks that will be called on every new connection
// internally in http.Server
type HTTPServerConnectionChainWrapper struct {
	net.Listener
	callbacks                  []ConnectionCallback
	connectionContextCallbacks []ConnectionContextCallback
}

// NewHTTPServerConnectionWrapper returns new wrapped Listener
func NewHTTPServerConnectionWrapper() (*HTTPServerConnectionChainWrapper, error) {
	return &HTTPServerConnectionChainWrapper{callbacks: make([]ConnectionCallback, 0, 4)}, nil
}

// SetListener sets listener that should be wrapped
func (wrapper *HTTPServerConnectionChainWrapper) SetListener(listener net.Listener) {
	wrapper.Listener = listener
}

// AddCallback register new callback for new connection from http.Server
func (wrapper *HTTPServerConnectionChainWrapper) AddCallback(callback ConnectionCallback) {
	wrapper.callbacks = append(wrapper.callbacks, callback)
}

// AddConnectionContextCallback add callback for OnConnectionContext calls
func (wrapper *HTTPServerConnectionChainWrapper) AddConnectionContextCallback(callback ConnectionContextCallback) {
	wrapper.connectionContextCallbacks = append(wrapper.connectionContextCallbacks, callback)
}

// OnConnectionContext implements http.Server.ConnContext handler signature and call registered callbacks
// If some of callback will return error then connection will be closed to prevent future usage
func (wrapper *HTTPServerConnectionChainWrapper) OnConnectionContext(ctx context.Context, c net.Conn) context.Context {
	var err error
	for _, callback := range wrapper.connectionContextCallbacks {
		ctx, err = callback.OnConnectionContext(ctx, c)
		if err != nil {
			log.WithError(err).Errorln("Error on OnConnectionContext call")
			if connErr := c.Close(); connErr != nil {
				log.WithError(err).Errorln("Error on connection close after error on OnConnectionContext call")
			}
		}
	}
	return ctx
}

// Unwrap returns wrapped listener
func (wrapper *HTTPServerConnectionChainWrapper) Unwrap() net.Listener {
	return wrapper.Listener
}

// CallbackError returned from OnConnection callbacks
type CallbackError struct {
	err error
}

// Error return Error() of wrapped error
func (e CallbackError) Error() string {
	return e.err.Error()
}

// Unwrap wrapped error
func (e CallbackError) Unwrap() error {
	return e.err
}

// errorConnection used for net.Listener implementation that should not return error on Accept call to not stop accepting new connections
// but prevent future usage of connection and return error on any Read/Write operation
type errorConnection struct {
	net.Conn
	err error
}

// SetDeadline return saved error for any SetDeadline call
func (e errorConnection) SetDeadline(t time.Time) error {
	return e.err
}

// SetReadDeadline return saved error for any SetReadDeadline call
func (e errorConnection) SetReadDeadline(t time.Time) error {
	return e.err
}

// SetWriteDeadline return saved error for any SetWriteDeadline call
func (e errorConnection) SetWriteDeadline(t time.Time) error {
	return e.err
}

// Read return saved error for any Read call
func (e errorConnection) Read(b []byte) (n int, err error) {
	return 0, e.err
}

// Write return saved error for any Write call
func (e errorConnection) Write(b []byte) (n int, err error) {
	return 0, e.err
}

// Accept call wrapped listener's Accept method and call all registered callbacks. Because this wrapper used as http.Server's
// listener and http.Server will shutdown on any error Accept method. If wrapped listener successfully Accepted new connection
// but any callback returned error than this method will return wrapped connection without any error. But this connection will
// return error from callback on any call of net.Conn method to prevent future usage and to avoid http.Server shutdown
func (wrapper *HTTPServerConnectionChainWrapper) Accept() (net.Conn, error) {
	if wrapper.Listener == nil {
		return nil, ErrListenerNotSet
	}
	conn, err := wrapper.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrappedConn := conn
	for i, callback := range wrapper.callbacks {
		wrappedConn, err = callback.OnConnection(wrappedConn)
		if err != nil {
			log.WithError(err).WithField("index", i).Errorln("Error on callback")
			// return ne
			return errorConnection{conn, err}, nil
		}
	}
	return wrappedConn, nil
}
