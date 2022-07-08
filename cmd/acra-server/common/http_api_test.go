package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/network/testutils"
	"github.com/gin-gonic/gin"
)

func getListener(connWrapper network.HTTPServerConnectionWrapper, t *testing.T) net.Listener {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	connWrapper.SetListener(listener)
	return connWrapper
}

func runWithServer(t *testing.T, keyStorage keystore.ServerKeyStore, tlsWrapper *network.TLSConnectionWrapper, callback func(url string)) {
	clientID := []byte("client")
	useClientIDFromCert := true

	config, err := NewConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.SetKeyStore(keyStorage)

	errChan := make(chan os.Signal)
	restartChan := make(chan os.Signal)
	sserver, err := NewEEAcraServerMainComponent(config, nil, errChan, restartChan)
	if err != nil {
		t.Fatal(err)
	}

	config.HTTPAPIConnectionWrapper, err = BuildHTTPAPIConnectionWrapper(tlsWrapper, useClientIDFromCert, clientID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errors := make(chan error)

	apiServer := NewHTTPAPIServer(
		ctx,
		sserver.config.GetKeyStore(),
		sserver.config.TraceToLog,
		sserver.config.GetTraceOptions(),
		sserver.config.GetTLSClientIDExtractor(),
		config.HTTPAPIConnectionWrapper.OnConnectionContext,
	)
	listener := getListener(config.HTTPAPIConnectionWrapper, t)
	defer listener.Close()
	go func() {
		errors <- apiServer.Start(listener, &sserver.backgroundWorkersSync)
	}()

	url := listener.Addr().String()

	callback(url)

	cancel()
	select {
	case err := <-errors:
		if err != nil {
			t.Fatal("server error", err)
		}
	case <-time.After(time.Millisecond * 10):
		t.Fatal("Timeout fired")
	}
}

func TestPlainHTTPAPI(t *testing.T) {

	keyStorage := &mocks.ServerKeyStore{}

	keyStorage.On("GenerateZoneKey").Return([]byte("id"), []byte("publicKey"), error(nil))
	keyStorage.On("GenerateZoneIDSymmetricKey", []byte("id")).Return(error(nil))
	keyStorage.On("Reset").Return()

	runWithServer(t, keyStorage, nil, func(url string) {
		t.Run("Test /getNewZone", func(t *testing.T) {
			response, err := http.Get(fmt.Sprintf("http://%s/getNewZone", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusOK {
				t.Fatalf("status code (%d) != %d", sc, http.StatusOK)
			}

			if ct := response.Header.Get("content-type"); ct != gin.MIMEJSON {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEJSON)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			// base64("publicKey") -> "cHVibGljS2V5"
			expectedBody := `{"id":"id","public_key":"cHVibGljS2V5"}`

			if !bytes.Equal(body, []byte(expectedBody)) {
				t.Fatalf("expected body %q, but found %q", expectedBody, body)
			}
		})

		t.Run("Test /resetKeyStorage", func(t *testing.T) {
			response, err := http.Get(fmt.Sprintf("http://%s/resetKeyStorage", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusOK {
				t.Fatalf("status code (%d) != %d", sc, http.StatusOK)
			}

			// Use `Contains` instead of `==` because Mime type can be
			// `text/plain; charset=utf-8`
			if ct := response.Header.Get("content-type"); !strings.Contains(ct, gin.MIMEPlain) {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEPlain)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}

			if len(body) != 0 {
				t.Fatalf("expected empty body, but found %q", body)
			}

			keyStorage.AssertCalled(t, "Reset")
		})

		t.Run("Test non-existed", func(t *testing.T) {
			response, err := http.Get(fmt.Sprintf("http://%s/GloryToUkraine", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusNotFound {
				t.Fatalf("status code (%d) != %d", sc, http.StatusNotFound)
			}

			// Use `Contains` instead of `==` because Mime type can be
			// `text/plain; charset=utf-8`
			if ct := response.Header.Get("content-type"); !strings.Contains(ct, gin.MIMEPlain) {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEPlain)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(body, []byte(errorRequestMessage)) {
				t.Fatalf("expected body %q, but found %q", errorRequestMessage, body)
			}
		})

		t.Run("TLS connection", func(t *testing.T) {
			_, client, _ := createTLSWrapper(t)
			_, err := client.Get(fmt.Sprintf("https://%s/getNewZone", url))
			expectedError := "http: server gave HTTP response to HTTPS client"
			if !strings.Contains(err.Error(), expectedError) {
				t.Fatalf("expected %q, but found %q", expectedError, err)
			}
		})
	})
}

func createTLSWrapper(t *testing.T) (*network.TLSConnectionWrapper, *http.Client, []byte) {
	tlsExtractor := newClientIDExtractor(t)
	serverTLSConfig, err := network.NewTLSConfig("127.0.0.1", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
	if err != nil {
		t.Fatal(err)
	}
	clientTLSConfig, err := network.NewTLSConfig("127.0.0.1", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, serverConfig, err := testutils.GetTestTLSConfigs(func() *tls.Config { return clientTLSConfig }, func() *tls.Config { return serverTLSConfig })
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := network.NewTLSAuthenticationHTTP2ConnectionWrapper(true, clientConfig, serverConfig, tlsExtractor)
	if err != nil {
		t.Fatal(err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = clientConfig
	client := &http.Client{Transport: transport}
	x509Cert, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := tlsExtractor.ExtractClientID(x509Cert)
	if err != nil {
		t.Fatal(err)
	}

	return serverWrapper, client, clientID
}

func newClientIDExtractor(t *testing.T) network.TLSClientIDExtractor {
	hexConverter, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	dnExtractor, err := network.NewIdentifierExtractorByType(network.IdentifierExtractorTypeDistinguishedName)
	if err != nil {
		t.Fatal(err)
	}
	tlsExtractor, err := network.NewTLSClientIDExtractor(dnExtractor, hexConverter)
	if err != nil {
		t.Fatal(err)
	}
	return tlsExtractor
}

func TestTLSHTTPAPI(t *testing.T) {
	serverWrapper, client, _ := createTLSWrapper(t)

	keyStorage := &mocks.ServerKeyStore{}

	keyStorage.On("GenerateZoneKey").Return([]byte("id"), []byte("publicKey"), error(nil))
	keyStorage.On("GenerateZoneIDSymmetricKey", []byte("id")).Return(error(nil))
	keyStorage.On("Reset").Return()

	runWithServer(t, keyStorage, serverWrapper, func(url string) {
		t.Run("Test /getNewZone", func(t *testing.T) {
			response, err := client.Get(fmt.Sprintf("https://%s/getNewZone", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusOK {
				t.Fatalf("status code (%d) != %d", sc, http.StatusOK)
			}

			if ct := response.Header.Get("content-type"); ct != gin.MIMEJSON {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEJSON)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			// base64("publicKey") -> "cHVibGljS2V5"
			expectedBody := `{"id":"id","public_key":"cHVibGljS2V5"}`

			if !bytes.Equal(body, []byte(expectedBody)) {
				t.Fatalf("expected body %q, but found %q", expectedBody, body)
			}
		})

		t.Run("Test /resetKeyStorage", func(t *testing.T) {
			response, err := client.Get(fmt.Sprintf("https://%s/resetKeyStorage", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusOK {
				t.Fatalf("status code (%d) != %d", sc, http.StatusOK)
			}

			// Use `Contains` instead of `==` because Mime type can be
			// `text/plain; charset=utf-8`
			if ct := response.Header.Get("content-type"); !strings.Contains(ct, gin.MIMEPlain) {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEPlain)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}

			if len(body) != 0 {
				t.Fatalf("expected empty body, but found %q", body)
			}

			keyStorage.AssertCalled(t, "Reset")
		})

		t.Run("Test non-existed", func(t *testing.T) {
			response, err := client.Get(fmt.Sprintf("https://%s/GloryToUkraine", url))
			if err != nil {
				t.Fatal(err)
			}

			if sc := response.StatusCode; sc != http.StatusNotFound {
				t.Fatalf("status code (%d) != %d", sc, http.StatusNotFound)
			}

			// Use `Contains` instead of `==` because Mime type can be
			// `text/plain; charset=utf-8`
			if ct := response.Header.Get("content-type"); !strings.Contains(ct, gin.MIMEPlain) {
				t.Fatalf("content-type (%s) != %s", ct, gin.MIMEPlain)
			}

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(body, []byte(errorRequestMessage)) {
				t.Fatalf("expected body %q, but found %q", errorRequestMessage, body)
			}
		})

		t.Run("plain connection", func(t *testing.T) {
			_, err := client.Get(fmt.Sprintf("http://%s/getNewZone", url))
			expectedError := "EOF"
			if !strings.Contains(err.Error(), expectedError) {
				t.Fatalf("expected %q, but found %q", expectedError, err)
			}
		})
	})

}

// Test that the client ID is successfully extracted from the certificate
func TestClientIDExtractedFromTLS(t *testing.T) {
	statiClientID := []byte("IvanSirko")
	tlsWrapper, client, expectedClientID := createTLSWrapper(t)
	useClientIDFromCert := true

	testClientID(t, tlsWrapper, useClientIDFromCert, client, "https", statiClientID, expectedClientID)
}

// Test that the TLS is used but the client ID is defined by the user
// (with the --client_id flag) for example.
func TestStaticClientIDTLS(t *testing.T) {
	tlsWrapper, client, _ := createTLSWrapper(t)
	clientID := []byte("some client id")
	useClientIDFromCert := false

	testClientID(t, tlsWrapper, useClientIDFromCert, client, "https", clientID, clientID)
}

// Test that the client id is defined by the user and no tls is used
func TestStaticClientIDPlain(t *testing.T) {
	clientID := []byte("some client id")
	useClientIDFromCert := false
	testClientID(t, nil, useClientIDFromCert, http.DefaultClient, "http", clientID, clientID)
}

func testClientID(
	t *testing.T,
	tlsWrapper *network.TLSConnectionWrapper,
	useClientIDFromCert bool,
	client *http.Client,
	protocol string,
	staticClientID []byte,
	expectedClientID []byte,
) {
	tlsExtractor := newClientIDExtractor(t)

	config, err := NewConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.SetTLSClientIDExtractor(tlsExtractor)

	config.HTTPAPIConnectionWrapper, err = BuildHTTPAPIConnectionWrapper(tlsWrapper, useClientIDFromCert, staticClientID)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	apiServer := NewHTTPAPIServer(
		ctx,
		config.GetKeyStore(),
		config.TraceToLog,
		config.GetTraceOptions(),
		config.GetTLSClientIDExtractor(),
		config.HTTPAPIConnectionWrapper.OnConnectionContext,
	)

	// inject endpoint for retrieving the client id
	apiServer.httpServer.Handler.(*gin.Engine).GET("/client_id", func(ctx *gin.Context) {
		clientID := ginGetClientID(ctx)
		ctx.JSON(http.StatusOK, clientID)
	})

	listener := getListener(config.HTTPAPIConnectionWrapper, t)
	defer listener.Close()

	errors := make(chan error)
	wait := sync.WaitGroup{}
	go func() {
		errors <- apiServer.Start(listener, &wait)
	}()

	url := listener.Addr().String()

	response, err := client.Get(fmt.Sprintf("%s://%s/client_id", protocol, url))
	if err != nil {
		t.Fatal(err)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Body: %q\n", body)

	var clientID []byte
	if err := json.Unmarshal(body, &clientID); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientID, expectedClientID) {
		t.Fatalf("Expected %q, but found %q", expectedClientID, clientID)
	}

	cancel()
	select {
	case err := <-errors:
		if err != nil {
			t.Fatal("server error", err)
		}
	case <-time.After(time.Millisecond * 10):
		t.Fatal("Timeout fired")
	}
}
