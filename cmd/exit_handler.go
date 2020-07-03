package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"
)


type Priority int

const (
	Last Priority = iota
	Indifferent
)

// SignalCallback callback function
type SignalCallback_ struct {
	callbackFunc func()
	priority     Priority
}

func NewSignalCallback(callback func(), priority Priority) *SignalCallback_ {
	return &SignalCallback_{
		callback,
		priority,
	}
}

func (s *SignalCallback_) GetPriority() Priority {
	return s.priority
}

func (s *SignalCallback_) Call() {
	s.callbackFunc()
}

// SignalHandler sends Signal to listeners and call registered callbacks
type SignalHandler_ struct {
	ch        chan os.Signal
	listeners []net.Listener
	callbacks []*SignalCallback_
	signals   []os.Signal
}

// NewSignalHandler returns new SignalHandler registered for particular os.Signals
func NewSignalHandler_(handledSignals []os.Signal) (*SignalHandler_, error) {
	return &SignalHandler_{ch: make(chan os.Signal), signals: handledSignals}, nil
}

// AddListener to listeners list
func (handler *SignalHandler_) AddListener(listener net.Listener) {
	handler.listeners = append(handler.listeners, listener)
}

// GetChannel returns channel of os.Signal
func (handler *SignalHandler_) GetChannel() chan os.Signal {
	return handler.ch
}

// AddCallback to callbacks list
func (handler *SignalHandler_) AddCallback(callback *SignalCallback_) {
	handler.callbacks = append(handler.callbacks, callback)
}

// Register should be called as goroutine
func (handler *SignalHandler_) Register() {
	signal.Notify(handler.ch, handler.signals...)

	<-handler.ch

	for _, listener := range handler.listeners {
		listener.Close()
	}
	for _, callback := range handler.callbacks {
		callback.Call()
	}
	os.Exit(0)
}

type AcraExitHandler interface {
	AddExitSignalHandler(signal AcraSignal, priority Priority)
	AddDeferFunc(deferFunc func(), priority Priority)
	ExitZero()
	ExitOne()
}

type ExitHandler struct {
	deferFunctions []DeferFunction
	signalHandlers []AcraSignal
	notification   chan os.Signal
}

func NewExitHandler() (*ExitHandler, error) {
	return &ExitHandler{
		deferFunctions: nil,
		signalHandlers: nil,
		notification:   make(chan os.Signal),
	}, nil
}

func NewSigTERMHandler() AcraSignal {
	return &SigTERMHandler{
		nil,
		nil,
	}
}

func NewSigINTHandler() AcraSignal {
	return &SigINTHandler{
		NewSigTERMHandler().(*SigTERMHandler),
	}
}

func (s *ExitHandler) AddExitSignalHandler(input AcraSignal) {
	s.signalHandlers = append(s.signalHandlers, input)
}

func (s *ExitHandler) waitForExitSystemSignal(exitFuncOnSigINT func(), exitFuncOnSigTERM func()) {
	signal.Notify(s.notification, s.getSignals()...)

	switch <-s.notification {
	case syscall.SIGINT:
		exitFuncOnSigINT()
	case syscall.SIGTERM:
		exitFuncOnSigTERM()
	}
}

func (s *ExitHandler) WaitForExitSystemSignal() {
	s.waitForExitSystemSignal(s.ExitZero, s.ExitZero)
}

func (s *ExitHandler) getSignals() []os.Signal {
	var result []os.Signal
	for _, signal := range s.signalHandlers {
		result = append(result, signal.GetSignal())
	}
	return result
}

func (s *ExitHandler) AddDeferFunc(input DeferFunction) {
	inputHasLastPriority := input.GetPriority() == Last
	for _, deferFunc := range s.deferFunctions {
		if deferFunc.GetPriority() == Last && inputHasLastPriority {
			panic("defer function with 'Last' priority has been already specified")
		}
	}
	s.deferFunctions = append(s.deferFunctions, input)
}

func (s *ExitHandler) ExitZero() {
	s.gracefulExit()
	os.Exit(0)
}

func (s *ExitHandler) ExitOne() {
	s.gracefulExit()
	os.Exit(1)
}

func (s *ExitHandler) gracefulExit() {
	// at first we finalize our handlers (close listeners and call callbacks)
	s.executeFinalizeOnHandlers()
	// finally we call defer functions
	s.executeDeferFunctions()
}

func (s *ExitHandler) executeDeferFunctions() {
	var lastDefer DeferFunction
	for _, deferFunction := range s.deferFunctions {
		if deferFunction.GetPriority() == Last {
			lastDefer = deferFunction
		}
		deferFunction.Call()
	}
	// defer function with last priority has not been found
	if lastDefer == nil {
		return
	}
	lastDefer.Call()
}

func (s *ExitHandler) executeFinalizeOnHandlers() {
	for _, handler := range s.signalHandlers {
		handler.Finalize()
	}
}

type AcraSignal interface {
	Finalize()
	GetSignal() os.Signal
	AddCallback(callback *SignalCallback_)
	AddListener(listener net.Listener)
}

// SIGTERM
type SigTERMHandler struct {
	listeners []net.Listener
	callbacks []*SignalCallback_
}

func (s *SigTERMHandler) AddCallback(input *SignalCallback_) {
	inputHasLastPriority := input.GetPriority() == Last
	for _, callback := range s.callbacks {
		if callback.GetPriority() == Last && inputHasLastPriority {
			panic("callback with 'Last' priority has been already specified")
		}
	}
	s.callbacks = append(s.callbacks, input)
}

// AddListener to listeners list
func (s *SigTERMHandler) AddListener(listener net.Listener) {
	s.listeners = append(s.listeners, listener)
}

func (s *SigTERMHandler) Finalize() {
	for _, listener := range s.listeners {
		listener.Close()
	}
	var lastCallback *SignalCallback_
	for _, callback := range s.callbacks {
		if callback.GetPriority() == Last {
			lastCallback = callback
		}
		callback.Call()
	}
	// defer function with last priority has not been found
	if lastCallback == nil {
		return
	}
	lastCallback.Call()
}

func (s *SigTERMHandler) GetSignal() os.Signal {
	return syscall.SIGTERM
}

// SIGINT (in Acra we do not distinguish between SIGINT and SIGTERM signals)
type SigINTHandler struct {
	handler *SigTERMHandler
}

func (s *SigINTHandler) Finalize() {
	s.handler.Finalize()
}

func (s *SigINTHandler) GetSignal() os.Signal {
	return syscall.SIGINT
}

// AddListener to listeners list
func (s *SigINTHandler) AddListener(listener net.Listener) {
	s.handler.AddListener(listener)
}

func (s *SigINTHandler) AddCallback(input *SignalCallback_) {
	s.handler.AddCallback(input)
}

type DeferFunction interface {
	GetPriority() Priority
	Call()
}

type DeferFunc struct {
	deferFunc func()
	priority  Priority
}

func NewDeferFunction(deferFunc func(), priority Priority) DeferFunction {
	return &DeferFunc{
		deferFunc,
		priority,
	}
}

func (d *DeferFunc) GetPriority() Priority {
	return d.priority
}

func (d *DeferFunc) Call() {
	d.deferFunc()
}
