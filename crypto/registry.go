package crypto

import (
	"errors"
	"github.com/cossacklabs/acra/keystore"
)

// Registry interface abstraction over crypto registry
// for keeping correspondence between ContainerHandlers and their IDs.
type Registry interface {
	Register(handler ContainerHandler) error
	GetHandlerByName(name string) (ContainerHandler, error)
	GetHandlerByEnvelopeID(envelopeID byte) (ContainerHandler, error)
}

// Registry related errors
var (
	ErrHandlerNotFound     = errors.New("handler not found in registry")
	ErrHandlerAlreadyExist = errors.New("handler with provided name already exist")
)

// MapRegistry implementation of Registry interface using Go map as storage
type mapRegistry struct {
	// will be used for encryption process according to encryptor's config
	envelopes map[string]ContainerHandler
	// will be used for decryption process according to serialized container ID
	handlerIDMap map[byte]ContainerHandler
}

// registry singleton for keeping all supported handlers
var registry *mapRegistry

// InitRegistry initialize registry singleton
// we can't initialize it in init function because AcraBlock/AcraStruct handlers should be able to access theirs KeyStores in runtime
// but KeyStore is initialized in main.go
func InitRegistry(keyStore keystore.ServerKeyStore) error {
	registry = &mapRegistry{
		envelopes:    make(map[string]ContainerHandler),
		handlerIDMap: make(map[byte]ContainerHandler),
	}
	if err := Register(NewAcraBlockHandler()); err != nil {
		return err
	}
	return Register(NewAcraStructHandler())
}

//Register public API allows registering other handlers from other packages
func Register(handler ContainerHandler) error {
	_, ok := registry.envelopes[handler.Name()]
	if ok {
		return ErrHandlerAlreadyExist
	}

	registry.envelopes[handler.Name()] = handler
	registry.handlerIDMap[handler.ID()] = handler
	return nil
}

// GetHandlerByName return ContainerHandler from storage by its name
func GetHandlerByName(name string) (ContainerHandler, error) {
	envelope, ok := registry.envelopes[name]
	if !ok {
		return nil, ErrHandlerNotFound
	}

	return envelope, nil
}

// GetHandlerByEnvelopeID return ContainerHandler from storage by its envelopID
func GetHandlerByEnvelopeID(envelopeID byte) (ContainerHandler, error) {
	handler, ok := registry.handlerIDMap[envelopeID]
	if !ok {
		return nil, ErrHandlerNotFound
	}

	return handler, nil
}
