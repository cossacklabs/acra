package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"
)

// Priority is applied to callback or defer function
type Priority int

const (
	Last Priority = iota
	Indifferent
)

// SignalCallback_ callback function with priority
type SignalCallback_ struct {
	callbackFunc func()
	priority     Priority
}

// NewSignalCallback creates a callback with priority
func NewSignalCallback(callback func(), priority Priority) *SignalCallback_ {
	return &SignalCallback_{
		callback,
		priority,
	}
}

// GetPriority is a getter for callback's priority
func (s *SignalCallback_) GetPriority() Priority {
	return s.priority
}

// Call executes callback
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

// AcraExitHandler is a common interface for exit handlers of Acra services
type AcraExitHandler interface {
	AddExitSignalHandler(signal AcraSignal, priority Priority)
	AddDeferFunc(deferFunc func(), priority Priority)
	ExitZero()
	ExitOne()
}

// ExitHandler is an implementation of AcraExitHandler
type ExitHandler struct {
	deferFunctions []DeferFunction
	signalHandlers []AcraSignal
	notification   chan os.Signal
}

// NewExitHandler is a constructor for ExitHandler
func NewExitHandler() (*ExitHandler, error) {
	return &ExitHandler{
		deferFunctions: nil,
		signalHandlers: nil,
		notification:   make(chan os.Signal),
	}, nil
}

// NewSigTERMHandler is a constructor for SigTERMHandler
func NewSigTERMHandler() AcraSignal {
	return &SigTERMHandler{
		nil,
		nil,
	}
}

// NewSigINTHandler is a constructor for SigINTHandler
func NewSigINTHandler() AcraSignal {
	return &SigINTHandler{
		NewSigTERMHandler().(*SigTERMHandler),
	}
}

// AddExitSignalHandler appends new signal for handling
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

// WaitForExitSystemSignal blocks and waits for signals.
// It should be used in separate goroutine in main function of service
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

// AddDeferFunc appends new defer function (with priority) for execution
func (s *ExitHandler) AddDeferFunc(input DeferFunction) {
	inputHasLastPriority := input.GetPriority() == Last
	for _, deferFunc := range s.deferFunctions {
		if deferFunc.GetPriority() == Last && inputHasLastPriority {
			panic("defer function with 'Last' priority has been already specified")
		}
	}
	s.deferFunctions = append(s.deferFunctions, input)
}

// ExitZero is a single point for exiting from the service with 0 code
func (s *ExitHandler) ExitZero() {
	s.gracefulExit()
	os.Exit(0)
}

// ExitOne is a single point for exiting from the service with 1 code
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

// AcraSignal is a common interface for system signal handlers in Acra
type AcraSignal interface {
	Finalize()
	GetSignal() os.Signal
	AddCallback(callback *SignalCallback_)
	AddListener(listener net.Listener)
}

// SigTERMHandler is an implementation of AcraSignal for SIGTERM signal
type SigTERMHandler struct {
	listeners []net.Listener
	callbacks []*SignalCallback_
}

// AddCallback appends callback with priority to SigTERMHandler
func (s *SigTERMHandler) AddCallback(input *SignalCallback_) {
	inputHasLastPriority := input.GetPriority() == Last
	for _, callback := range s.callbacks {
		if callback.GetPriority() == Last && inputHasLastPriority {
			panic("callback with 'Last' priority has been already specified")
		}
	}
	s.callbacks = append(s.callbacks, input)
}

// AddListener appends listener to SigTERMHandler
func (s *SigTERMHandler) AddListener(listener net.Listener) {
	s.listeners = append(s.listeners, listener)
}

// Finalize closes all listeners and executes callbacks with priority considering
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

// GetSignal returns underlying constant that represents system signal
func (s *SigTERMHandler) GetSignal() os.Signal {
	return syscall.SIGTERM
}

// SigINTHandler is an implementation of AcraSignal for SIGINT signal (in Acra we do not distinguish between SIGINT and SIGTERM signals)
type SigINTHandler struct {
	handler *SigTERMHandler
}

// Finalize closes all listeners and executes callbacks with priority considering
func (s *SigINTHandler) Finalize() {
	s.handler.Finalize()
}

// GetSignal returns underlying constant that represents system signal
func (s *SigINTHandler) GetSignal() os.Signal {
	return syscall.SIGINT
}

// AddListener appends listener to SigINTHandler
func (s *SigINTHandler) AddListener(listener net.Listener) {
	s.handler.AddListener(listener)
}

// AddCallback appends callback with priority to SigINTHandler
func (s *SigINTHandler) AddCallback(input *SignalCallback_) {
	s.handler.AddCallback(input)
}

// DeferFunction is a common interface for defer function with priority to execution
type DeferFunction interface {
	GetPriority() Priority
	Call()
}

// DeferFunc is an implementation of DeferFunction
type DeferFunc struct {
	deferFunc func()
	priority  Priority
}

// NewDeferFunction is a constructor for DeferFunction
func NewDeferFunction(deferFunc func(), priority Priority) DeferFunction {
	return &DeferFunc{
		deferFunc,
		priority,
	}
}

// GetPriority returns priority of execution for this defer function
func (d *DeferFunc) GetPriority() Priority {
	return d.priority
}

// Call just executes defer function
func (d *DeferFunc) Call() {
	d.deferFunc()
}
