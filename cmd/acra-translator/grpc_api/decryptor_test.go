package grpc_api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils/tests"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/stretchr/testify/assert"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const connectionTimeout = time.Second

// newTestKeystore return keystore implementation with generated keypairs for encryption/decryption and poison record purposes
func newTestKeystore(t *testing.T) *testKeystore {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	poisonKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeystore{EncryptionKeypair: keypair, PoisonKey: poisonKeypair}
}

// testgRPCServer start gRPC server as gorountine using unix socket
type testgRPCServer struct {
	listener net.Listener
	server   *grpc.Server
	unixPath string
}

func newServer(data *common.TranslatorData, opts []grpc.ServerOption, t *testing.T) *testgRPCServer {
	factory := &GRPCServerFactory{}
	server, err := factory.New(data, opts...)
	if err != nil {
		t.Fatal(err)
	}
	unixPath, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(unixPath.Name())
	listener, err := net.Listen("unix", unixPath.Name())
	if err != nil {
		t.Fatal(err)
	}

	go server.Serve(listener)
	return &testgRPCServer{listener: listener, server: server, unixPath: unixPath.Name()}
}

// newServerTLSgRPCOpts returns server options to use TLS as transport using keys from tests/ssl/[ca|acra-server]
func newServerTLSgRPCOpts(t *testing.T) []grpc.ServerOption {
	verifier := network.NewCertVerifierAll()
	workingDirectory := tests.GetSourceRootDirectory(t)
	serverConfig, err := network.NewTLSConfig("localhost", filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"), filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.key"), filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.crt"), 4, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(serverConfig))}
}

func newClientTLSConfig(t *testing.T) *tls.Config {
	verifier := network.NewCertVerifierAll()
	workingDirectory := tests.GetSourceRootDirectory(t)
	clientConfig, err := network.NewTLSConfig("localhost", filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"), 4, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return clientConfig
}

func newClientTLSgRPCOpts(config *tls.Config, t *testing.T) []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(config))}
}

func (server *testgRPCServer) Stop() {
	server.server.Stop()
	server.listener.Close()
}

func getgRPCUnixDialer()grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("unix", addr)
	})
}
func getSecureSessionDialer(wrapper *network.SecureSessionConnectionWrapper) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err :=  net.Dial("unix", addr)
		if err != nil {
			return nil, err
		}
		conn, err = wrapper.WrapClient(context.Background(), conn)
		if err != nil {
			return nil, err
		}
		ctx, _ = trace.StartSpan(ctx, "WrapClient")
		if err := network.SendTrace(ctx, conn); err != nil {
			return nil, err
		}
		return conn, err
	})
}

func (server *testgRPCServer) NewConnection(opts []grpc.DialOption, t *testing.T) *grpc.ClientConn {
	ctx, _ := context.WithTimeout(context.Background(), connectionTimeout)
	conn, err := grpc.DialContext(ctx, server.unixPath, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestNewFactoryWithClientIDFromTLSConnection(t *testing.T) {
	idConvertor, err := network.NewDefaultHexIdentifierConverter()
	if err != nil {
		t.Fatal(err)
	}
	idExtractor, err := network.NewTLSClientIDExtractor(&network.DistinguishedNameExtractor{}, idConvertor)
	if err != nil {
		t.Fatal(err)
	}
	tlsExtractor, err := network.NewTLSGRPCClientIDExtractor(idExtractor)
	if err != nil {
		t.Fatal(err)
	}
	keystorage := newTestKeystore(t)
	data := &common.TranslatorData{UseConnectionClientID: true, Keystorage: keystorage, ConnectionClientIDExtractor: tlsExtractor}
	serverOpts := newServerTLSgRPCOpts(t)
	server := newServer(data, serverOpts, t)
	defer server.Stop()
	clientConfig := newClientTLSConfig(t)
	clientOpts := newClientTLSgRPCOpts(clientConfig, t)
	clientOpts = append(clientOpts, getgRPCUnixDialer())
	conn := server.NewConnection(clientOpts, t)
	defer conn.Close()

	writerClient := NewWriterClient(conn)
	ctx := context.Background()
	testdata := []byte("some data")
	encryptResponse, err := writerClient.Encrypt(ctx, &EncryptRequest{Data: testdata})
	if err != nil {
		t.Fatal(err)
	}
	x509ClientCert, err := x509.ParseCertificate(clientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedClientId, err := idExtractor.ExtractClientID(x509ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedClientId, keystorage.UsedID)

	readerClient := NewReaderClient(conn)
	decryptResponse, err := readerClient.Decrypt(ctx, &DecryptRequest{Acrastruct: encryptResponse.Acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expectedClientId, keystorage.UsedID)
	assert.Equal(t, testdata, decryptResponse.Data)
}

func TestNewFactoryWithClientIDFromSecureSessionConnectionSuccess(t *testing.T) {
	extractor, err := network.NewSecureSessionGRPCClientIDExtractor()
	if err != nil {
		t.Fatal(err)
	}
	keystorage := newTestKeystore(t)
	data := &common.TranslatorData{UseConnectionClientID: true, Keystorage: keystorage, ConnectionClientIDExtractor: extractor}
	testClientID := []byte("some id")
	secureSessionWrapper, err := network.NewSecureSessionConnectionWrapper(testClientID, keystorage)
	if err != nil {
		t.Fatal(err)
	}
	serverOpts := []grpc.ServerOption{grpc.Creds(secureSessionWrapper)}
	server := newServer(data, serverOpts, t)
	defer server.Stop()
	clientOpts := []grpc.DialOption{getSecureSessionDialer(secureSessionWrapper), grpc.WithInsecure()}
	conn := server.NewConnection(clientOpts, t)
	defer conn.Close()

	writerClient := NewWriterClient(conn)
	testdata := []byte("some data")
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	encryptResponse, err := writerClient.Encrypt(ctx, &EncryptRequest{Data: testdata})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testClientID, keystorage.UsedID)

	readerClient := NewReaderClient(conn)
	decryptResponse, err := readerClient.Decrypt(ctx, &DecryptRequest{Acrastruct: encryptResponse.Acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, testClientID, keystorage.UsedID)
	assert.Equal(t, testdata, decryptResponse.Data)
}

func TestNewFactoryWithClientIDFromSecureSessionConnectionInvalidAuthInfo(t *testing.T) {
	extractor, err := network.NewSecureSessionGRPCClientIDExtractor()
	if err != nil {
		t.Fatal(err)
	}
	keystorage := newTestKeystore(t)
	data := &common.TranslatorData{UseConnectionClientID: true, Keystorage: keystorage, ConnectionClientIDExtractor: extractor}
	serverOpts := []grpc.ServerOption{}
	server := newServer(data, serverOpts, t)
	defer server.Stop()
	clientOpts := []grpc.DialOption{grpc.WithInsecure(), getgRPCUnixDialer()}
	conn := server.NewConnection(clientOpts, t)
	defer conn.Close()

	writerClient := NewWriterClient(conn)
	testdata := []byte("some data")
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	_, err = writerClient.Encrypt(ctx, &EncryptRequest{Data: testdata})
	grpcErr, ok := status.FromError(err)
	if !ok {
		t.Fatal("incorrect error type, expected gRPC error")
	}
	if !strings.EqualFold(grpcErr.Message(), network.ErrIncorrectGRPCConnectionAuthInfo.Error()){
		t.Fatalf("incorrect error from gRPC request. took: %s, expects: %s\n", grpcErr.Message(), network.ErrCantExtractClientID)
	}

	readerClient := NewReaderClient(conn)
	_, err = readerClient.Decrypt(ctx, &DecryptRequest{Acrastruct: testdata})
	grpcErr, ok = status.FromError(err)
	if !ok {
		t.Fatal("incorrect error type, expected gRPC error")
	}
	if !strings.EqualFold(grpcErr.Message(), network.ErrIncorrectGRPCConnectionAuthInfo.Error()){
		t.Fatalf("incorrect error from gRPC request. took: %s, expects: %s\n", grpcErr.Message(), network.ErrCantExtractClientID)
	}
}