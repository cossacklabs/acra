package testutils

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/utils/tests"
	"github.com/jackc/pgx/v5/pgproto3"
	"io"
	"net"
	"reflect"
)

// Frontend extends pgproto3.Frontend
type Frontend struct {
	*pgproto3.Frontend
	connIn, connOut net.Conn
}

// NewFrontend returns new Frontend
func NewFrontend(connIn, connOut net.Conn) *Frontend {
	f := pgproto3.NewFrontend(connIn, connOut)
	return &Frontend{Frontend: f, connIn: connIn, connOut: connOut}
}

const (
	SSLRequestOk = 'S'
	SSLRequestNo = 'N'
)

// ReadSSLResponse reads and returns response on SSLRequest
func (f *Frontend) ReadSSLResponse() (byte, error) {
	var out [1]byte
	_, err := f.connIn.Read(out[:])
	return out[0], err
}

func (f *Frontend) SwitchToTLS(ctx context.Context, tlsConfig *tls.Config) error {
	newConn := tls.Client(f.connOut, tlsConfig)
	if err := newConn.HandshakeContext(ctx); err != nil {
		return err
	}
	f.Frontend = pgproto3.NewFrontend(newConn, newConn)
	return nil
}

// Step execute one step of flow
type Step interface {
	Step(*Frontend) error
}

// Script store and run steps until gets error
type Script struct {
	Steps []Step
}

// Run runs all steps until error
func (s *Script) Run(frontend *Frontend) error {
	for _, step := range s.Steps {
		err := step.Step(frontend)
		if err != nil {
			return err
		}
	}

	return nil
}

// Step whole script works as one step
func (s *Script) Step(frontend *Frontend) error {
	return s.Run(frontend)
}

type expectMessageStep struct {
	want pgproto3.BackendMessage
	any  bool
}

// Step receives one message from the frontend and verify that it is fully equal to the expected message
func (e *expectMessageStep) Step(frontend *Frontend) error {
	msg, err := frontend.Receive()
	if err != nil {
		return err
	}

	if e.any && reflect.TypeOf(msg) == reflect.TypeOf(e.want) {
		return nil
	}

	if !reflect.DeepEqual(msg, e.want) {
		return fmt.Errorf("msg => %#v, e.want => %#v", msg, e.want)
	}

	return nil
}

// ExpectMessage creates step to receive one packet and verify that it deeply equals to "want" message
func ExpectMessage(want pgproto3.BackendMessage) Step {
	return expectMessage(want, false)
}

// ExpectAnyMessage creates step to receive one packet and compare only the type with "want"s type
func ExpectAnyMessage(want pgproto3.BackendMessage) Step {
	return expectMessage(want, true)
}

func expectMessage(want pgproto3.BackendMessage, any bool) Step {
	return &expectMessageStep{want: want, any: any}
}

type sendMessageStep struct {
	msg pgproto3.FrontendMessage
}

// Step send message to frontends buffer
func (e *sendMessageStep) Step(frontend *Frontend) error {
	frontend.Send(e.msg)
	return nil
}

// SendMessage sends message to the frontend's buffer but not flushes. It will be sent only on buffer overload or FlushStep
func SendMessage(msg pgproto3.FrontendMessage) Step {
	return &sendMessageStep{msg: msg}
}

type waitForStep struct{ wants pgproto3.BackendMessage }

// Step skips messages from the frontend until gets message with required type
func (e *waitForStep) Step(frontend *Frontend) error {
	for {
		msg, err := frontend.Receive()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}

		if reflect.TypeOf(msg) == reflect.TypeOf(e.wants) {
			return nil
		}
		continue
	}
}

// WaitForStep creates step that skips all messages from the frontend until gets message with msg's type
func WaitForStep(msg pgproto3.BackendMessage) Step {
	return &waitForStep{msg}
}

type flushStep struct{}

// Step flushes frontend's buffer and really sends messages to the connection
func (f flushStep) Step(frontend *Frontend) error {
	return frontend.Flush()
}

// NewFlushStep returns step that flushes frontend's buffer and sends collected packets to the connection
func NewFlushStep() Step {
	return flushStep{}
}

type authStep struct {
	database, username, password string
	ctx                          context.Context
	tlsConfig                    *tls.Config
}

// NewAuthStep returns step to send Startup message and process authentication with password md5 authentication
func NewAuthStep(ctx context.Context, tlsConfig *tls.Config, database, username, password string) Step {
	return authStep{database: database, username: username, password: password, ctx: ctx, tlsConfig: tlsConfig}
}

// Step authenticates to database and wait completion of authentication phase
func (step authStep) Step(frontend *Frontend) error {
	if tests.TestWithTLS() {
		frontend.Send(&pgproto3.SSLRequest{})
		if err := frontend.Flush(); err != nil {
			return err
		}
		response, err := frontend.ReadSSLResponse()
		if err != nil {
			return err
		}
		if response == SSLRequestNo {
			return errors.New("postgresql denied SSLRequest")
		}
		if err = frontend.SwitchToTLS(step.ctx, step.tlsConfig); err != nil {
			return err
		}
	}

	frontend.Send(&pgproto3.StartupMessage{pgproto3.ProtocolVersionNumber, map[string]string{
		"user":     step.username,
		"database": step.database,
	}})
	err := frontend.Flush()
	if err != nil {
		return err
	}
	msg, err := frontend.Receive()
	if err != nil {
		return err
	}
	_, ok := msg.(*pgproto3.AuthenticationOk)
	if ok {
		return WaitForStep(&pgproto3.ReadyForQuery{}).Step(frontend)
	}
	md5Msg, ok := msg.(*pgproto3.AuthenticationMD5Password)
	if !ok {
		return fmt.Errorf("msg => %#v, e.want => %#v", msg, &pgproto3.AuthenticationMD5Password{})
	}
	// took from github.com/jackc/pgx/v5@v5.2.0/pgconn/pgconn.go
	hexMD5 := func(s string) string {
		hash := md5.New()
		io.WriteString(hash, s)
		return hex.EncodeToString(hash.Sum(nil))
	}
	digestedPassword := "md5" + hexMD5(hexMD5(step.password+step.username)+string(md5Msg.Salt[:]))
	frontend.Send(&pgproto3.PasswordMessage{Password: digestedPassword})
	err = frontend.Flush()
	if err != nil {
		return err
	}
	return WaitForStep(&pgproto3.ReadyForQuery{}).Step(frontend)
}

// RowData represents row of DataRow
type RowData [][]byte

// CollectDataRowsStep used to receive and store rows from the database DataRow response
type CollectDataRowsStep struct {
	count int
	rows  []RowData
}

// NewCollectDataRowsStep creates step that collects <count> DataRow packet's values and export them
func NewCollectDataRowsStep(count int) *CollectDataRowsStep {
	return &CollectDataRowsStep{count: count}
}

// GetRows returns collected rows
func (step *CollectDataRowsStep) GetRows() []RowData {
	return step.rows
}

// Step receive and store DataRow packets count times
func (step *CollectDataRowsStep) Step(frontend *Frontend) error {
	step.rows = make([]RowData, step.count)
	for i := 0; i < step.count; i++ {
		msg, err := frontend.Receive()
		if err != nil {
			return err
		}
		dataRow, ok := msg.(*pgproto3.DataRow)
		if !ok {
			return fmt.Errorf("msg => %#v, e.want => %#v", msg, &pgproto3.DataRow{})
		}
		// make copies
		for _, value := range dataRow.Values {
			step.rows[i] = append(step.rows[i], append([]byte{}, value...))
		}
	}
	return nil
}
