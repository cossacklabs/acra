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
	Indifferent Priority = iota
	Last
)

// SystemSignalCallback callback function with priority
type SystemSignalCallback struct {
	callbackFunc func()
	priority     Priority
}

// NewSystemSignalCallback creates a callback with priority
func NewSystemSignalCallback(callback func(), priority Priority) *SystemSignalCallback {
	return &SystemSignalCallback{
		callback,
		priority,
	}
}

// GetPriority is a getter for callback's priority
func (s *SystemSignalCallback) GetPriority() Priority {
	return s.priority
}

// Call executes callback
func (s *SystemSignalCallback) Call() {
	s.callbackFunc()
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
		SigTERMHandler{
			nil,
			nil,
		},
	}
}

// AddExitSignalHandler appends new signal for handling
func (s *ExitHandler) AddExitSignalHandler(input AcraSignal) {
	s.signalHandlers = append(s.signalHandlers, input)
}

func (s *ExitHandler) waitAndHandle(exitFuncOnSigINT func(), exitFuncOnSigTERM func()) {
	signal.Notify(s.notification, s.getSignals()...)

	switch <-s.notification {
	case syscall.SIGINT:
		exitFuncOnSigINT()
	case syscall.SIGTERM:
		exitFuncOnSigTERM()
	}
}

// WaitAndHandle blocks and waits for signals.
// It should be used in separate goroutine in main function of service
func (s *ExitHandler) WaitAndHandle() {
	s.waitAndHandle(s.ExitSuccess, s.ExitSuccess)
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

// ExitSuccess is a single point for exiting from the service with 0 code
func (s *ExitHandler) ExitSuccess() {
	s.gracefulExit()
	os.Exit(0)
}

// ExitFailure is a single point for exiting from the service with 1 code
func (s *ExitHandler) ExitFailure() {
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
	AddCallback(callback *SystemSignalCallback)
	AddListener(listener net.Listener)
}

// SigTERMHandler is an implementation of AcraSignal for SIGTERM signal
type SigTERMHandler struct {
	listeners []net.Listener
	callbacks []*SystemSignalCallback
}

// AddCallback appends callback with priority to SigTERMHandler
func (s *SigTERMHandler) AddCallback(input *SystemSignalCallback) {
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
	var lastCallback *SystemSignalCallback
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
	SigTERMHandler
}

// GetSignal returns underlying constant that represents system signal
func (s *SigINTHandler) GetSignal() os.Signal {
	return syscall.SIGINT
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
