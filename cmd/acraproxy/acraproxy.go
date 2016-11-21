package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	. "github.com/cossacklabs/acra/utils"
	"bytes"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/session"
)

const (
	MIN_LENGTH_CLIENT_ID = 4
	MAX_LENGTH_CLIENT_ID = 256
)

type ClientSession struct {
	Config *Config
}

func (session *ClientSession) StateChanged(ss *session.SecureSession, state int) {}

func (client_session *ClientSession) GetPublicKeyForId(ss *session.SecureSession, id []byte) *keys.PublicKey {
	if bytes.Compare(client_session.Config.AcraId, id) != 0 {
		log.Printf("Warning: incorrect server id - %v\n", string(id))
		return nil
	}
	log.Printf("Debug: use %v server's public key\n", fmt.Sprintf("%v/%v_server.pub", client_session.Config.KeysDir, string(client_session.Config.ClientId)))
	// try to open file in PUBLIC_KEYS_DIR directory where pub file should be named like <client_id>.pub
	key, _ := LoadPublicKey(fmt.Sprintf("%v/%v_server.pub", client_session.Config.KeysDir, string(client_session.Config.ClientId)))
	return key
}

func NewClientSession(config *Config) (*session.SecureSession, error) {
	log.Printf("Debug: use private key: %v\n", fmt.Sprintf("%v/%v", config.KeysDir, string(config.ClientId)))
	private_key, err := LoadPrivateKey(fmt.Sprintf("%v/%v", config.KeysDir, string(config.ClientId)))
	if err != nil {
		return nil, err
	}
	ssession, err := session.New(config.ClientId, private_key, &ClientSession{Config: config})
	if err != nil {
		return nil, err
	}
	return ssession, nil
}

func initializeSecureSession(config *Config, connection net.Conn) (*session.SecureSession, error) {
	err := SendData(config.ClientId, connection)
	if err != nil {
		return nil, err
	}
	log.Println("Debug: create ssession")
	ssession, err := NewClientSession(config)
	if err != nil {
		return nil, err
	}
	connect_request, err := ssession.ConnectRequest()
	if err != nil {
		return nil, err
	}
	err = SendData(connect_request, connection)
	if err != nil {
		return nil, err
	}
	for {
		data, err := ReadData(connection)
		if err != nil {
			return nil, err
		}
		buf, sendPeer, err := ssession.Unwrap(data)
		if nil != err {
			return nil, err
		}

		if !sendPeer {
			log.Println("Debug: initialized secure session")
			return ssession, nil
		}

		err = SendData(buf, connection)
		if err != nil {
			return nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return ssession, nil
		}
	}
}

func proxyClientConnections(client_connection, acra_connection net.Conn, session *session.SecureSession, err_ch chan<- error) {
	// postgresql usually use 8kb for buffers
	buf := make([]byte, 8192)
	for {
		n, err := client_connection.Read(buf)
		if err != nil {
			err_ch <- err
			return
		}
		encrypted_data, err := session.Wrap(buf[:n])
		if err != nil {
			err_ch <- err
			return
		}
		err = SendData(encrypted_data, acra_connection)
		if err != nil {
			err_ch <- err
			return
		}
		if n == 8192 {
			log.Printf("Debug: used full acraproxy buffer. Increase size to 2x from %v to %v\n", len(buf), len(buf)*2)
			buf = make([]byte, len(buf)*2)
		}
	}
}

func proxyAcraConnections(client_connection, acra_connection net.Conn, session *session.SecureSession, err_ch chan<- error) {
	for {
		data, err := ReadData(acra_connection)
		if err != nil {
			err_ch <- err
			return
		}
		decrypted_data, _, err := session.Unwrap(data)
		if err != nil {
			err_ch <- err
			return
		}
		n, err := client_connection.Write(decrypted_data)
		if err != nil {
			err_ch <- err
			return
		}
		if n != len(decrypted_data) {
			err_ch <- errors.New("sent incorrect bytes count")
			return
		}
	}
}

func handleClientConnection(config *Config, connection net.Conn) {
	defer connection.Close()

	acra_conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", config.AcraHost, config.AcraPort))
	if err != nil {
		log.Printf("Error: %v\n", ErrorMessage("can't connect to acra", err))
		return
	}
	defer acra_conn.Close()
	ssession, err := initializeSecureSession(config, acra_conn)
	if err != nil {
		log.Printf("Error: %v\n", ErrorMessage("can't initialize secure session", err))
		return
	}
	err_ch := make(chan error)
	log.Println("Debug: secure session initialized")
	go proxyClientConnections(connection, acra_conn, ssession, err_ch)
	go proxyAcraConnections(connection, acra_conn, ssession, err_ch)
	err = <-err_ch
	if err != nil {
		if err == io.EOF {
			log.Println("Debug: connection closed")
		} else {
			log.Println("Error: ", err)
		}
		return
	}
}

type Config struct {
	KeysDir  string
	ClientId []byte
	AcraId   []byte
	AcraHost string
	AcraPort int
	Port     int
}

func main() {
	keys_dir := flag.String("keys_dir", "~/.ssession", "dir where private app key and public acra key")
	client_id := flag.String("client_id", "", "client id should be name of file with private key")
	acra_host := flag.String("acra_host", "", "ip or domain to acra daemon")
	acra_commands_port := flag.Int("acra_commands_port", 9090, "port of acra commands daemon")
	acra_port := flag.Int("acra_port", 9393, "port of acra daemon")
	acra_id := flag.String("acra_id", "acra_server", "expected id from acra server for Secure Session")
	verbose := flag.Bool("v", false, "log to stdout")
	port := flag.Int("port", 9494, "port for proxy from")
	commands_port := flag.Int("command_port", 9191, "port for accepting command connection")
	flag.Parse()

	if len(*client_id) <= MIN_LENGTH_CLIENT_ID {
		fmt.Printf("Error: client id length <= %v. Use longer than %v\n", MIN_LENGTH_CLIENT_ID, MIN_LENGTH_CLIENT_ID)
		flag.Usage()
		os.Exit(1)
	}
	if len(*client_id) >= MAX_LENGTH_CLIENT_ID {
		fmt.Printf("Error: client id length >= %v. Use less than %v\n", MAX_LENGTH_CLIENT_ID, MAX_LENGTH_CLIENT_ID)
		flag.Usage()
		os.Exit(1)
	}
	client_private_key := fmt.Sprintf("%v%v%v", *keys_dir, string(os.PathSeparator), *client_id)
	server_public_key := fmt.Sprintf("%v%v%v_server.pub", *keys_dir, string(os.PathSeparator), *client_id)
	exists, err := FileExists(client_private_key)
	if !exists {
		fmt.Printf("Error: acraproxy private key %s doesn't exists\n", client_private_key)
		os.Exit(1)
	}
	if err != nil {
		fmt.Printf("Error: can't check is exists acraproxy private key %v, got error - %v\n", client_private_key, err)
		os.Exit(1)
	}
	exists, err = FileExists(server_public_key)
	if !exists {
		fmt.Printf("Error: acraserver public key %s doesn't exists\n", server_public_key)
		os.Exit(1)
	}
	if err != nil {
		fmt.Printf("Error: can't check is exists acraserver public key %v, got error - %v\n", server_public_key, err)
		os.Exit(1)
	}
	if *acra_host == "" {
		fmt.Println("Error: you must specify host to acra")
		flag.Usage()
		os.Exit(1)
	}

	if *verbose {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	config := &Config{KeysDir: *keys_dir, ClientId: []byte(*client_id), AcraHost: *acra_host, AcraPort: *acra_port, Port: *port, AcraId: []byte(*acra_id)}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", *port))
	if err != nil {
		log.Printf("Error: %v\n", ErrorMessage("can't start listen connections", err))
		os.Exit(1)
	}
	go func() {
		commands_config := &Config{KeysDir: *keys_dir, ClientId: []byte(*client_id), AcraHost: *acra_host, AcraPort: *acra_commands_port, Port: *commands_port, AcraId: []byte(*acra_id)}
		commands_listener, err := net.Listen("tcp", fmt.Sprintf(":%v", *commands_port))
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage("can't start listen connections to http api", err))
			os.Exit(1)
		}
		fmt.Printf("Info: start listening http api %v\n", *commands_port)
		for {
			connection, err := commands_listener.Accept()
			if err != nil {
				log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
				continue
			}
			log.Printf("Info: new connection to http api: %v\n", connection.RemoteAddr())
			go handleClientConnection(commands_config, connection)
		}
	}()

	fmt.Printf("Info: start listening %v\n", *port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
			os.Exit(1)
		}
		log.Printf("Info: new connection: %v\n", connection.RemoteAddr())
		go handleClientConnection(config, connection)
	}
}
