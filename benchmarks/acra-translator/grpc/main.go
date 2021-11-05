/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd/acra-translator/grpc_api"
	"github.com/cossacklabs/acra/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"testing"
)

// BenchTLSAcraBlock run AcraBlock TLS benchmarking test
func BenchTLSAcraBlock(connectionString, serverName, clientID, zoneID, data, ca, key, cert string, authType int) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ctx := context.Background()
			tlsConfig, err := network.NewTLSConfig(serverName, ca, key, cert, tls.ClientAuthType(authType), network.NewCertVerifierAll())
			if err != nil {
				b.Fatal(err)
			}
			opts := []grpc.DialOption{}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			conn, err := grpc.Dial(connectionString, opts...)
			if err != nil {
				b.Fatal(err)
			}
			client := grpc_api.NewWriterSymClient(conn)
			readClient := grpc_api.NewReaderSymClient(conn)
			for i := 0; i < b.N; i++ {
				resp, err := client.EncryptSym(ctx, &grpc_api.EncryptSymRequest{Data: []byte(data), ClientId: []byte(clientID), ZoneId: []byte(zoneID)})
				if err != nil {
					b.Fatal(err)
				}

				resp2, err := readClient.DecryptSym(ctx, &grpc_api.DecryptSymRequest{Acrablock: resp.Acrablock, ClientId: []byte(clientID), ZoneId: []byte(zoneID)})
				if err != nil {
					b.Fatal(err)
				}
				if string(resp2.Data) != data {
					b.Fatal("invalid decryption")
				}
			}
		}
	}
}

// BenchTLSAcraStruct run AcraStruct TLS benchmarking test
func BenchTLSAcraStruct(connectionString, serverName, clientID, zoneID, data, ca, key, cert string, authType int) func(b *testing.B) {
	return func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ctx := context.Background()
			tlsConfig, err := network.NewTLSConfig(serverName, ca, key, cert, tls.ClientAuthType(authType), network.NewCertVerifierAll())
			if err != nil {
				b.Fatal(err)
			}
			opts := []grpc.DialOption{}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			conn, err := grpc.Dial(connectionString, opts...)
			if err != nil {
				b.Fatal(err)
			}
			client := grpc_api.NewWriterClient(conn)
			readClient := grpc_api.NewReaderClient(conn)
			for i := 0; i < b.N; i++ {
				resp, err := client.Encrypt(ctx, &grpc_api.EncryptRequest{Data: []byte(data), ClientId: []byte(clientID), ZoneId: []byte(zoneID)})
				if err != nil {
					b.Fatal(err)
				}

				resp2, err := readClient.Decrypt(ctx, &grpc_api.DecryptRequest{Acrastruct: resp.Acrastruct, ClientId: []byte(clientID), ZoneId: []byte(zoneID)})
				if err != nil {
					b.Fatal(err)
				}
				if string(resp2.Data) != data {
					b.Fatal("invalid decryption")
				}
			}
		}
	}
}

func main() {
	ca := flag.String("tls_ca", "ca.crt", "TLS CA file")
	key := flag.String("tls_key", "acra-writer.key", "TLS private key")
	cert := flag.String("tls_crt", "acra-writer.crt", "TLS certificate")
	authType := flag.Int("tls_auth", 0, "TLS auth type")
	connectionString := flag.String("connection_string", "127.0.0.1:9696", "host:port to AcraTranslator")
	serverName := flag.String("tls_server_sni", "localhost", "Server name of AcraTranslator")
	clientID := flag.String("client_id", "client", "Client id used in request")
	zoneID := flag.String("zone_id", "", "Zone id used in request")
	data := flag.String("data", "some data", "Data sent to encrypt/decrypt")
	flag.Parse()

	type benchData struct {
		Name   string
		Result testing.BenchmarkResult
	}
	result := make([]benchData, 0, 10)
	result = append(result, benchData{Name: "TLS + AcraBlock", Result: testing.Benchmark(BenchTLSAcraBlock(*connectionString, *serverName, *clientID, *zoneID, *data, *ca, *key, *cert, *authType))})
	result = append(result, benchData{Name: "TLS + AcraStruct", Result: testing.Benchmark(BenchTLSAcraStruct(*connectionString, *serverName, *clientID, *zoneID, *data, *ca, *key, *cert, *authType))})
	for _, res := range result {
		fmt.Printf("%s - %s\n", res.Name, res.Result.String())
	}
}
