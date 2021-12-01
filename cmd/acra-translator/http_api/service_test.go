package http_api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	translatorCommon "github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/network/testutils"
	"github.com/cossacklabs/acra/pseudonymization"
	pseudonymizationCommon "github.com/cossacklabs/acra/pseudonymization/common"
	tokenStorage "github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"
)

type dialer func(ctx context.Context, network, addr string) (net.Conn, error)

func getDialer(wrapper network.ConnectionWrapper, t *testing.T) dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// use localhost instead ip to support tls connections with valid server names
		addr = strings.Replace(addr, "127.0.0.1", "localhost", -1)
		conn, err := net.DialTimeout(network, addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		ctx, _ = context.WithDeadline(ctx, time.Now().Add(time.Second*5))
		conn, err = wrapper.WrapClient(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		return conn, err
	}
}

type wrapperImplementation interface {
	network.ConnectionWrapper
	network.ConnectionCallback
}

func getListenerAndDialer(clientWrapper, serverWrapper wrapperImplementation, t *testing.T) (net.Listener, func(ctx context.Context, network, addr string) (net.Conn, error)) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerWrapper, err := network.NewHTTPServerConnectionWrapper()
	if err != nil {
		t.Fatal(err)
	}
	listenerWrapper.SetListener(listener)
	listenerWrapper.AddCallback(serverWrapper)
	return listenerWrapper, getDialer(clientWrapper, t)
}

func waitConnection(network, addr string, t *testing.T) {
	for i := 0; i < 10; i++ {
		conn, err := net.Dial(network, addr)
		if err != nil {
			time.Sleep(time.Millisecond * 10)
			continue
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("Can't wait established connection")
}

type testData struct {
	testString string
	testInt    int
	testEmail  string
	testBytes  []byte
	zoneID     []byte
}

func initKeyStore(clientID, zoneID []byte, keyStorage *mocks.ServerKeyStore, t *testing.T) {
	// reset expected calls
	keyStorage.ExpectedCalls = []*mock.Call{}

	acraBlockSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	acraBlockZoneKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	hmacSymKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	// TODO use poison callbacks and keys
	//poisonSymKey, err := keystore.GenerateSymmetricKey()
	//if err != nil {
	//	t.Fatal(err)
	//}

	//poisonKeyPair, err := keys.New(keys.TypeEC)
	//if err != nil {
	//	t.Fatal(err)
	//}
	AcraStructKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	AcraStructZoneKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	// everytime return copy of value because it will be zeroized after each call
	//keyStorage.On("GetPoisonSymmetricKeys").Return(func() [][]byte { return [][]byte{append([]byte{}, poisonSymKey...)} }, nil)
	keyStorage.On("GetClientIDSymmetricKeys", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, clientID)
	})).Return(func([]byte) [][]byte { return [][]byte{append([]byte{}, acraBlockSymKey...)} }, nil)
	keyStorage.On("GetHMACSecretKey", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, clientID)
	})).Return(func([]byte) []byte { return append([]byte{}, hmacSymKey...) }, nil)

	keyStorage.On("GetZonePublicKey", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, zoneID)
	})).Return(AcraStructZoneKeyPair.Public, nil)
	keyStorage.On("GetZonePrivateKeys", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, zoneID)
	})).Return(func([]byte) []*keys.PrivateKey {
		return []*keys.PrivateKey{{Value: append([]byte{}, AcraStructZoneKeyPair.Private.Value...)}}
	}, nil)
	keyStorage.On("GetZoneIDSymmetricKeys", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, zoneID)
	})).Return(func([]byte) [][]byte { return [][]byte{append([]byte{}, acraBlockZoneKey...)} }, nil)
	keyStorage.On("GetClientIDEncryptionPublicKey", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, clientID)
	})).Return(AcraStructKeyPair.Public, nil)
	keyStorage.On("GetServerDecryptionPrivateKeys", mock.MatchedBy(func(id []byte) bool {
		return bytes.Equal(id, clientID)
	})).Return(func([]byte) []*keys.PrivateKey {
		return []*keys.PrivateKey{{Value: append([]byte{}, AcraStructKeyPair.Private.Value...)}}
	}, nil)

}

func TestHTTPAPI(t *testing.T) {
	keyStorage := &mocks.ServerKeyStore{}
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
	listenerWrapper, err := network.NewHTTPServerConnectionWrapper()
	if err != nil {
		t.Fatal(err)
	}
	listenerWrapper.AddConnectionContextCallback(translatorCommon.ConnectionToContextCallback{})
	storage, err := tokenStorage.NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}
	tokenizer, err := pseudonymization.NewPseudoanonymizer(storage)
	if err != nil {
		t.Fatal(err)
	}
	translatorData := &translatorCommon.TranslatorData{Keystorage: keyStorage, TLSClientIDExtractor: tlsExtractor,
		Tokenizer: tokenizer}
	serviceImplementation, err := translatorCommon.NewTranslatorService(translatorData)
	if err != nil {
		t.Fatal(err)
	}
	zoneID := zone.GenerateZoneID()
	t.Run("HTTP API with Secure Session", func(t *testing.T) {
		testClientID := []byte("clientid")
		initKeyStore(testClientID, zoneID, keyStorage, t)
		secureSessionKeyPair, err := keys.New(keys.TypeEC)
		if err != nil {
			t.Fatal(err)
		}
		keyStorage.On("GetPrivateKey", mock.Anything).Return(secureSessionKeyPair.Private, nil)
		keyStorage.On("GetPeerPublicKey", mock.Anything).Return(secureSessionKeyPair.Public, nil)
		clientWrapper, err := network.NewSecureSessionConnectionWrapperWithServerID(testClientID, testClientID, keyStorage)
		if err != nil {
			t.Fatal(err)
		}
		serverWrapper, err := network.NewSecureSessionConnectionWrapper(testClientID, keyStorage)
		if err != nil {
			t.Fatal(err)
		}
		newListener, newDialer := getListenerAndDialer(clientWrapper, serverWrapper, t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		service, err := NewHTTPService(serviceImplementation, translatorData, WithContext(ctx), WithConnectionContextHandler(listenerWrapper.OnConnectionContext))
		if err != nil {
			t.Fatal(err)
		}

		outErr := make(chan error)
		go func(service *HTTPService, listener net.Listener, errCh chan error) {
			errCh <- service.Start(listener)
		}(service, newListener, outErr)

		waitConnection(newListener.Addr().Network(), newListener.Addr().String(), t)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = newDialer
		client := &http.Client{Transport: transport}
		testContext := apiTestContext{
			endpoint: fmt.Sprintf("http://%s", newListener.Addr()),
			zoneID:   zoneID,
			listener: newListener,
			client:   client,
		}
		testHTTPAPIEndpoints(testContext, t)
		// stop server
		cancel()
		select {
		case err := <-outErr:
			if err != http.ErrServerClosed {
				t.Fatal(err)
			}
		case <-time.NewTimer(time.Millisecond * 10).C:
			t.Fatal("Can't wait server stop")
		}
	})
	t.Run("test with direct TLS connections", func(t *testing.T) {
		serverTLSConfig, err := network.NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
		if err != nil {
			t.Fatal(err)
		}
		clientTLSConfig, err := network.NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
		if err != nil {
			t.Fatal(err)
		}
		clientConfig, serverConfig, err := testutils.GetTestTLSConfigs(func() *tls.Config { return clientTLSConfig }, func() *tls.Config { return serverTLSConfig })
		if err != nil {
			t.Fatal(err)
		}
		clientWrapper, err := network.NewTLSAuthenticationHTTP2ConnectionWrapper(true, clientConfig, serverConfig, tlsExtractor)
		if err != nil {
			t.Fatal(err)
		}
		serverWrapper, err := network.NewTLSAuthenticationHTTP2ConnectionWrapper(true, clientConfig, serverConfig, tlsExtractor)
		if err != nil {
			t.Fatal(err)
		}
		crt, err := x509.ParseCertificate(clientTLSConfig.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}

		expectedClientID, err := tlsExtractor.ExtractClientID(crt)
		if err != nil {
			t.Fatal(err)
		}
		initKeyStore(expectedClientID, zoneID, keyStorage, t)
		newListener, _ := getListenerAndDialer(clientWrapper, serverWrapper, t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		service, err := NewHTTPService(serviceImplementation, translatorData, WithContext(ctx), WithConnectionContextHandler(listenerWrapper.OnConnectionContext))
		if err != nil {
			t.Fatal(err)
		}

		outErr := make(chan error)
		go func(service *HTTPService, listener net.Listener, errCh chan error) {
			errCh <- service.Start(listener)
		}(service, newListener, outErr)

		waitConnection(newListener.Addr().Network(), newListener.Addr().String(), t)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = clientConfig
		client := &http.Client{Transport: transport}
		testContext := apiTestContext{
			endpoint: fmt.Sprintf("https://%s", newListener.Addr()),
			zoneID:   zoneID,
			listener: newListener,
			client:   client,
		}
		testHTTPAPIEndpoints(testContext, t)
		cancel()

		select {
		case err := <-outErr:
			if err != http.ErrServerClosed {
				t.Fatal(err)
			}
		case <-time.NewTimer(time.Millisecond * 10).C:
			t.Fatal("Can't wait server stop")
		}
	})
	t.Run("test with TLS connections over wrapper", func(t *testing.T) {
		serverTLSConfig, err := network.NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
		if err != nil {
			t.Fatal(err)
		}
		clientTLSConfig, err := network.NewTLSConfig("localhost", "", "", "", tls.RequireAndVerifyClientCert, network.NewCertVerifierAll())
		if err != nil {
			t.Fatal(err)
		}
		clientConfig, serverConfig, err := testutils.GetTestTLSConfigs(func() *tls.Config { return clientTLSConfig }, func() *tls.Config { return serverTLSConfig })
		if err != nil {
			t.Fatal(err)
		}
		clientWrapper, err := network.NewTLSAuthenticationHTTP2ConnectionWrapper(true, clientConfig, serverConfig, tlsExtractor)
		if err != nil {
			t.Fatal(err)
		}
		serverWrapper, err := network.NewTLSAuthenticationHTTP2ConnectionWrapper(true, clientConfig, serverConfig, tlsExtractor)
		if err != nil {
			t.Fatal(err)
		}
		crt, err := x509.ParseCertificate(clientTLSConfig.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}

		expectedClientID, err := tlsExtractor.ExtractClientID(crt)
		if err != nil {
			t.Fatal(err)
		}
		initKeyStore(expectedClientID, zoneID, keyStorage, t)
		newListener, newDialer := getListenerAndDialer(clientWrapper, serverWrapper, t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		service, err := NewHTTPService(serviceImplementation, translatorData, WithContext(ctx), WithConnectionContextHandler(listenerWrapper.OnConnectionContext))
		if err != nil {
			t.Fatal(err)
		}
		outErr := make(chan error)
		go func(service *HTTPService, listener net.Listener, errCh chan error) {
			errCh <- service.Start(listener)
		}(service, newListener, outErr)
		waitConnection(newListener.Addr().Network(), newListener.Addr().String(), t)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = newDialer
		client := &http.Client{Transport: transport}
		testContext := apiTestContext{
			endpoint: fmt.Sprintf("http://%s", newListener.Addr()),
			zoneID:   zoneID,
			listener: newListener,
			client:   client,
		}
		testHTTPAPIEndpoints(testContext, t)
		cancel()
		select {
		case err := <-outErr:
			if err != http.ErrServerClosed {
				t.Fatal(err)
			}
		case <-time.NewTimer(time.Millisecond * 10).C:
			t.Fatal("Can't wait server stop")
		}
	})
}

type apiTestContext struct {
	zoneID   []byte
	client   *http.Client
	listener net.Listener
	endpoint string
}

func testHTTPAPIEndpoints(testContext apiTestContext, t *testing.T) {
	expectedData := encryptData{testBytes: []byte("some bytes")}
	testOperationPairs := []struct {
		forwardOperation  string
		backwardOperation string
	}{
		{forwardOperation: encryptOperation, backwardOperation: decryptOperation},
		{forwardOperation: encryptSymOperation, backwardOperation: decryptSymOperation},
		{forwardOperation: encryptSearchableOperation, backwardOperation: decryptSearchableOperation},
		{forwardOperation: encryptSymSearchableOperation, backwardOperation: decryptSymSearchableOperation},
	}
	for _, testPair := range testOperationPairs {
		expectedData.zoneID = nil
		// test without zoneID
		testEncryptDecrypt(testContext.endpoint, http.MethodGet, testPair.forwardOperation, testPair.backwardOperation, expectedData, testContext.client, t)
		testEncryptDecrypt(testContext.endpoint, http.MethodPost, testPair.forwardOperation, testPair.backwardOperation, expectedData, testContext.client, t)

		// test with ZoneID
		expectedData.zoneID = testContext.zoneID
		testEncryptDecrypt(testContext.endpoint, http.MethodGet, testPair.forwardOperation, testPair.backwardOperation, expectedData, testContext.client, t)
		testEncryptDecrypt(testContext.endpoint, http.MethodPost, testPair.forwardOperation, testPair.backwardOperation, expectedData, testContext.client, t)
	}
	b64binaryData := base64.StdEncoding.EncodeToString([]byte(`some binary datadata`))
	b64BinaryJSONData := fmt.Sprintf(`"%s"`, b64binaryData)
	testTokenizeData := []tokenData{
		// string literals
		{nil, []byte(`"some json string"`), pseudonymizationCommon.TokenType_String},
		{nil, []byte(b64BinaryJSONData), pseudonymizationCommon.TokenType_Bytes},
		{nil, []byte(`"some@email.com"`), pseudonymizationCommon.TokenType_Email},
		// int json literals
		{nil, []byte(`123`), pseudonymizationCommon.TokenType_Int32},
		{nil, []byte(`321`), pseudonymizationCommon.TokenType_Int64},
	}
	for _, testTokenData := range testTokenizeData {
		testTokenData.ZoneID = []byte{}
		// test without zoneID
		testTokenizeDetokenize(testContext.endpoint, http.MethodGet, testTokenData, testContext.client, t)
		testTokenizeDetokenize(testContext.endpoint, http.MethodPost, testTokenData, testContext.client, t)

		// test with ZoneID
		testTokenData.ZoneID = testContext.zoneID
		testTokenizeDetokenize(testContext.endpoint, http.MethodGet, testTokenData, testContext.client, t)
		testTokenizeDetokenize(testContext.endpoint, http.MethodPost, testTokenData, testContext.client, t)
	}
}

type encryptData struct {
	testBytes []byte
	zoneID    []byte
}

func testEncryptDecrypt(endpoint, method, encryptOperationURL, decryptOperationURL string, data encryptData, client *http.Client, t *testing.T) {
	switch method {
	case http.MethodGet, http.MethodPost:
		break
	default:
		t.Fatalf("Unsupported method '%s' of http request\n", method)
	}
	requestTemplate, err := template.New("").Parse(`
    {
		"data": "{{.Base64Data}}",
		"zone_id": "{{.ZoneID}}"
        
    }`)
	if err != nil {
		t.Fatal(err)
	}
	type requestData struct {
		Base64Data string
		ZoneID     string
	}
	outputBuffer := bytes.Buffer{}
	if err := requestTemplate.Execute(&outputBuffer, requestData{
		Base64Data: base64.StdEncoding.EncodeToString(data.testBytes), ZoneID: string(data.zoneID),
	}); err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(method, fmt.Sprintf("%s/v2/%s", endpoint, encryptOperationURL), &outputBuffer)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", gin.MIMEJSON)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	responseObject := encryptionHTTPResponse{}
	if err := json.Unmarshal(responseBody, &responseObject); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data.testBytes, responseObject.Data) {
		t.Fatal("Encrypted data equal to source data")
	}
	outputBuffer.Reset()
	if err := requestTemplate.Execute(&outputBuffer, requestData{
		Base64Data: base64.StdEncoding.EncodeToString(responseObject.Data), ZoneID: string(data.zoneID),
	}); err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequest(method, fmt.Sprintf("%s/v2/%s", endpoint, decryptOperationURL), &outputBuffer)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", gin.MIMEJSON)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	responseObject = encryptionHTTPResponse{}
	if err := json.Unmarshal(responseBody, &responseObject); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data.testBytes, responseObject.Data) {
		t.Fatal("Decrypted data not equal to source data")
	}
}

type tokenData struct {
	ZoneID []byte
	Data   []byte
	Type   pseudonymizationCommon.TokenType
}

func testTokenizeDetokenize(endpoint, method string, data tokenData, client *http.Client, t *testing.T) {
	switch method {
	case http.MethodGet, http.MethodPost:
		break
	default:
		t.Fatalf("Unsupported method '%s' of http request\n", method)
	}

	tokenizeRequest := tokenizationHTTPRequest{Type: data.Type, ZoneID: data.ZoneID, Data: data.Data}
	requestJSON, err := json.Marshal(tokenizeRequest)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(method, fmt.Sprintf("%s/v2/%s", endpoint, tokenizeOperation), bytes.NewReader(requestJSON))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", gin.MIMEJSON)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, response.StatusCode, 200)
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	type rawResponse struct{ Data json.RawMessage }
	rawResponseObject := rawResponse{}
	if err := json.Unmarshal(responseBody, &rawResponseObject); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawResponseObject.Data, data.Data) {
		t.Fatal("Tokenized data equal to source data")
	}

	tokenizeRequest = tokenizationHTTPRequest{Type: data.Type, ZoneID: data.ZoneID, Data: rawResponseObject.Data}
	requestJSON, err = json.Marshal(tokenizeRequest)
	if err != nil {
		t.Fatal(err)
	}

	request, err = http.NewRequest(method, fmt.Sprintf("%s/v2/%s", endpoint, detokenizeOperation), bytes.NewReader(requestJSON))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", gin.MIMEJSON)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, response.StatusCode, 200)
	responseBody, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(responseBody, &rawResponseObject); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data.Data, rawResponseObject.Data) {
		t.Fatal("Detokenized data not equal to source data")
	}
}

func init() {
	if err := crypto.InitRegistry(nil); err != nil {
		panic(err)
	}
}
