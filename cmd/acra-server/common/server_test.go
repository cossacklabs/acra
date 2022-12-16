package common

import (
	"context"
	"fmt"
	"github.com/cossacklabs/acra/network"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

type panicConnectionWrapper struct {
	panicUsed bool
}

func (e *panicConnectionWrapper) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	e.panicUsed = true
	panic("implement me")
}

func (e *panicConnectionWrapper) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, []byte, error) {
	e.panicUsed = true
	panic("implement me")
}

func TestSServer_StartServer(t *testing.T) {
	config, err := NewConfig()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &panicConnectionWrapper{}
	config.ConnectionWrapper = wrapper
	unixFile, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(unixFile.Name()); err != nil {
		t.Fatal(err)
	}
	config.acraConnectionString = fmt.Sprintf("unix://%s", unixFile.Name())
	errCh := make(chan os.Signal, 1)
	restartCh := make(chan os.Signal, 1)
	server, err := NewEEAcraServerMainComponent(config, nil, errCh, restartCh)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	group := sync.WaitGroup{}
	readCh := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			conn, err := network.Dial(config.acraConnectionString)
			if err != nil {
				time.Sleep(time.Millisecond * 100)
				continue
			}
			go func() {
				buf := make([]byte, 10)
				if _, err = conn.Read(buf); err == nil {
					t.Fatal("Unexpected successful read")
				}
				readCh <- struct{}{}
			}()
			select {
			case <-readCh:
				break
			case <-time.NewTimer(time.Second).C:
				conn.Close()
				cancel()
				t.Fatal("Blocked on read")
			}
			if wrapper.panicUsed {
				cancel()
				server.Exit(nil)
				return
			}
			t.Fatal("Panic wasn't called")
		}
		t.Fatal("Can't connect")
	}()
	serverStop := make(chan struct{})
	go func() {
		t.Log("Start server")
		err = server.StartServer(ctx, &group, false)
		if err != nil {
			t.Log("Server error")
			t.Fatal(err)
		}
		t.Log("Server stopped")
		serverStop <- struct{}{}
	}()
	select {
	case <-serverStop:
		break
	case <-time.NewTimer(time.Second).C:
		t.Fatal("Server didn't stop")
	}
	if !wrapper.panicUsed {
		t.Fatal("Panic wasn't alled")
	}
	cancel()
	server.StopListeners()
}
