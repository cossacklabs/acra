package mysql

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNewMysqlCopyTextBoundValue(t *testing.T) {
	t.Run("textData not equals - success", func(t *testing.T) {
		sourceData := []byte("test-data")
		boundValue := NewMysqlCopyTextBoundValue(sourceData, base.BinaryFormat, TypeBlob)

		sourceData[0] = 22

		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(sourceData, value) {
			t.Fatal("BoundValue data should not be equal to sourceData")
		}
	})

	t.Run("nil data provided", func(t *testing.T) {
		boundValue := NewMysqlCopyTextBoundValue(nil, base.BinaryFormat, TypeBlob)
		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		// we need to validate that textData is nil if nil was provided - required for handling NULL values
		if value != nil {
			t.Fatal("BoundValue data should be nil")
		}
	})
}

// columnPacketHex is mysql test column packet with Name `id` and table `test_type_aware_decryption_without_defaults`
var columnPacketHex = "0364656604746573742b746573745f747970655f61776172655f64656372797074696f6e5f776974686f75745f64656661756c74732b746573745f747970655f61776172655f64656372797074696f6e5f776974686f75745f64656661756c74730269640269640c3f000b000000030342000000"

// paramPacketHex is mysql test param packet with Name `?` and table `test_type_aware_decryption_without_defaults`
var paramPacketHex = "03646566000000013f000c3f0000000000fd8000000000"

func TestColumnsTrackHandler(t *testing.T) {
	data, err := hex.DecodeString(columnPacketHex)
	if err != nil {
		t.Fatal(err)
	}

	parser := sqlparser.New(sqlparser.ModeStrict)

	testConfig := `
schemas:
  - table: test_type_aware_decryption_without_defaults
    columns:
      - id
    encrypted:
      - column: id
        data_type: "str"
`
	schemaStore, err := config.MapTableSchemaStoreFromConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}

	setting := base.NewProxySetting(parser, schemaStore, nil, nil, nil, nil, false)
	proxyHandler, err := NewMysqlProxy(&stubSession{}, parser, setting)
	if err != nil {
		t.Fatal()
	}

	fieldTracker := NewPreparedStatementFieldTracker(proxyHandler, 1)

	fieldPacket := NewPacket()
	fieldPacket.SetData(data)

	server, client := net.Pipe()
	deadline := time.Now().Add(time.Second)
	client.SetWriteDeadline(deadline)
	server.SetReadDeadline(deadline)

	defer client.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)
	// starting server connection read goroutine
	go func() {
		defer wg.Done()
		resData := make([]byte, len(fieldPacket.data)+len(fieldPacket.header))
		_, err := server.Read(resData)
		if err != nil {
			t.Fatal(err)
		}

		resPacket := NewPacket()
		// without header which is 4 bytes
		resPacket.SetData(resData[4:])
		resDesc, err := ParseResultField(resPacket)
		if err != nil {
			t.Fatal(err)
		}

		if resDesc.Type != TypeString {
			t.Fatalf("result packet type should be %d (string) but was %d", TypeString, resDesc.Type)
		}
	}()

	err = fieldTracker.ColumnsTrackHandler(context.Background(), fieldPacket, server, client)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestParamsTrackHandler(t *testing.T) {
	data, err := hex.DecodeString(paramPacketHex)
	if err != nil {
		t.Fatal(err)
	}

	parser := sqlparser.New(sqlparser.ModeStrict)
	nonEmptyStore := &tableSchemaStore{false}

	setting := base.NewProxySetting(parser, nonEmptyStore, nil, nil, nil, nil, false)
	proxyHandler, err := NewMysqlProxy(&stubSession{}, parser, setting)
	if err != nil {
		t.Fatal()
	}

	fieldTracker := NewPreparedStatementFieldTracker(proxyHandler, 1)

	fieldPacket := NewPacket()
	fieldPacket.SetData(data)

	server, client := net.Pipe()

	deadline := time.Now().Add(time.Second)
	client.SetWriteDeadline(deadline)
	server.SetReadDeadline(deadline)

	defer client.Close()

	t.Run("ParamsTrackHandler success", func(t *testing.T) {
		wg := sync.WaitGroup{}
		wg.Add(1)
		// starting server connection read goroutine
		go func() {
			defer wg.Done()
			resData := make([]byte, len(fieldPacket.data)+len(fieldPacket.header))
			_, err := server.Read(resData)
			if err != nil {
				t.Fatal(err)
			}

			resPacket := NewPacket()
			// without header which is 4 bytes
			resPacket.SetData(resData[4:])
			resField, err := ParseResultField(resPacket)
			if err != nil {
				t.Fatal(err)
			}

			if resField.Type != TypeLong {
				t.Fatalf("result packet type should be %d (int32) but was %d", TypeLong, resField.Type)
			}
		}()

		clientSession := &mocks.ClientSession{}
		sessionData := make(map[int]config.ColumnEncryptionSetting, 2)
		sessionData[0] = &config.BasicColumnEncryptionSetting{
			DataType: "int32",
		}
		clientSession.On("GetData", "bind_encryption_settings").Return(sessionData, true)

		ctx := base.SetClientSessionToContext(context.Background(), clientSession)
		err = fieldTracker.ParamsTrackHandler(ctx, fieldPacket, server, client)
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
	})

	t.Run("ParamsTrackHandler with nil items map", func(t *testing.T) {
		wg := sync.WaitGroup{}
		wg.Add(1)
		// starting server connection read goroutine
		go func() {
			defer wg.Done()
			resData := make([]byte, len(fieldPacket.data)+len(fieldPacket.header))
			_, err := server.Read(resData)
			if err != nil {
				t.Fatal(err)
			}

			resPacket := NewPacket()
			// without header which is 4 bytes
			resPacket.SetData(resData[4:])
			if !bytes.Equal(fieldPacket.GetData(), resData[4:]) {
				t.Fatal("result packet should be as origin packet")
			}
		}()

		clientSession := &mocks.ClientSession{}
		clientSession.On("GetData", "bind_encryption_settings").Return(nil, true)

		ctx := base.SetClientSessionToContext(context.Background(), clientSession)
		err = fieldTracker.ParamsTrackHandler(ctx, fieldPacket, server, client)
		if err != nil {
			t.Fatal(err)
		}
		wg.Wait()
	})
}
