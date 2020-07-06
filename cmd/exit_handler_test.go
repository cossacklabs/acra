package cmd

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDeferFunctionsPriority(t *testing.T) {
	exitHandler, err := NewExitHandler()
	if err != nil {
		t.Fatal(err)
	}

	// we use slice of strings that will be filled by defer functions
	var results []string

	auditLogDefer := func() {
		// we need that logFinalize to be called strictly as last defer function
		results = append(results, "audit_log defer")
	}
	stubDefer1 := func() {
		results = append(results, "stub1 defer")
	}
	stubDefer2 := func() {
		results = append(results, "stub2 defer")
	}

	exitHandler.AddDeferFunc(NewDeferFunction(auditLogDefer, Last))
	exitHandler.AddDeferFunc(NewDeferFunction(stubDefer1, Indifferent))
	exitHandler.AddDeferFunc(NewDeferFunction(stubDefer2, Indifferent))

	exitHandler.executeDeferFunctions()

	// finally check indication of last string in results
	if results[len(results)-1] != "audit_log defer" {
		t.Fatal("auditLogDefer has not been executed as last defer")
	}
}

func TestExitHandler(t *testing.T) {
	testExitHandler(t, syscall.SIGTERM)
	testExitHandler(t, syscall.SIGINT)
	testExitHandlerWithCallbacks(t, syscall.SIGTERM)
	testExitHandlerWithCallbacks(t, syscall.SIGINT)
}

func testExitHandlerWithCallbacks(t *testing.T, signalToExit os.Signal) {
	exitHandler, err := NewExitHandler()
	if err != nil {
		t.Fatal(err)
	}

	sigTERMHandler := NewSigTERMHandler()
	sigINTHandler := NewSigINTHandler()

	var results []string
	auditLogCallback := func() {
		// put special messages strictly in the end of log stream
		results = append(results, "audit_log callback")
	}

	stubCallback1 := func() {
		// some other stuff like Prometheus server stop
		results = append(results, "Prometheus stop 1 callback")
	}

	stubCallback2 := func() {
		// some other stuff like Prometheus server stop
		results = append(results, "Prometheus stop 2 callback")
	}

	// create exit signal handlers and feed them to common exit handler mechanism
	sigTERMHandler.AddCallback(NewSystemSignalCallback(auditLogCallback, Last))
	sigTERMHandler.AddCallback(NewSystemSignalCallback(stubCallback1, Indifferent))
	sigTERMHandler.AddCallback(NewSystemSignalCallback(stubCallback2, Indifferent))

	sigINTHandler.AddCallback(NewSystemSignalCallback(auditLogCallback, Last))
	sigINTHandler.AddCallback(NewSystemSignalCallback(stubCallback1, Indifferent))
	sigINTHandler.AddCallback(NewSystemSignalCallback(stubCallback2, Indifferent))

	exitHandler.AddExitSignalHandler(sigTERMHandler)
	exitHandler.AddExitSignalHandler(sigINTHandler)

	go func() {
		time.Sleep(time.Millisecond * 50)
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		err = process.Signal(signalToExit)
		if err != nil {
			t.Fatal(err)
		}
	}()

	exitHandler.waitAndHandle(exitHandler.gracefulExit, exitHandler.gracefulExit)

	// finally check indication of last string in results
	if results[len(results)-1] != "audit_log callback" {
		t.Fatal("auditLogCallback has not been executed as last callback")
	}
}

func testExitHandler(t *testing.T, signalToExit os.Signal) {
	exitHandler, err := NewExitHandler()
	if err != nil {
		t.Fatal(err)
	}

	exitHandler.AddExitSignalHandler(NewSigTERMHandler())
	exitHandler.AddExitSignalHandler(NewSigINTHandler())

	go func() {
		time.Sleep(time.Millisecond * 50)
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		err = process.Signal(signalToExit)
		if err != nil {
			t.Fatal(err)
		}
	}()

	exitHandler.waitAndHandle(exitHandler.gracefulExit, exitHandler.gracefulExit)
}
