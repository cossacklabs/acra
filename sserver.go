package acra

import (
	. "github.com/cossacklabs/acra/utils"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cossacklabs/themis/gothemis/session"
)

const (
	INIT_SSESSION_TIMEOUT = 30 * time.Second
)

type SServer struct {
	config *Config
}

func NewServer(config *Config) (server *SServer, err error) {
	server = &SServer{config: config}
	return
}

/*
 initialize SecureSession with new connection
 read client_id, load public key for this client and initialize Secure Session
*/
func (server *SServer) initSSession(connection net.Conn) (*ClientSession, error) {
	client_id, err := ReadData(connection)
	if err != nil {
		return nil, err
	}
	client_session, err := NewClientSession(client_id, server.config, connection)
	if err != nil {
		return nil, err
	}
	ssession, err := session.New(server.config.GetServerId(), client_session.server_private_key, client_session)
	if err != nil {
		return nil, err
	}
	client_session.session = ssession
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
			return client_session, nil
		}

		err = SendData(buf, connection)
		if err != nil {
			return nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return client_session, err
		}
	}
}

func (server *SServer) getDecryptor(client_session *ClientSession) Decryptor {
	var keystore KeyStore
	if server.config.GetWithZone() {
		keystore = NewFilesystemKeyStore(server.config.GetKeysDir())
	} else {
		keystore = NewOneKeyStore(client_session.GetServerPrivateKey())
	}

	var data_decryptor DataDecryptor
	var matcher_pool *MatcherPool
	if server.config.GetByteaFormat() == HEX_BYTEA_FORMAT {
		data_decryptor = NewPgHexDecryptor()
		matcher_pool = NewMatcherPool(NewPgHexMatcherFactory())
	} else {
		data_decryptor = NewPgEscapeDecryptor()
		matcher_pool = NewMatcherPool(NewPgEscapeMatcherFactory())
	}
	decryptor := NewPgDecryptor(data_decryptor)
	decryptor.SetWithZone(server.config.GetWithZone())
	decryptor.SetKeyStore(keystore)
	decryptor.SetPoisonKey(server.config.GetPoisonKey())
	zone_matcher := NewZoneMatcher(matcher_pool, keystore)
	decryptor.SetZoneMatcher(zone_matcher)

	poison_callback_storage := NewPoisonCallbackStorage()
	if server.config.GetScriptOnPoison() != "" {
		poison_callback_storage.AddCallback(NewExecuteScriptCallback(server.config.GetScriptOnPoison()))
	}
	// must be last
	if server.config.GetStopOnPoison() {
		poison_callback_storage.AddCallback(&StopCallback{})
	}
	decryptor.SetPoisonCallbackStorage(poison_callback_storage)
	return decryptor
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	client_session, err := server.initSSession(connection)
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't initialize secure session with acraproxy", err))
		connection.Close()
		return
	}
	defer client_session.session.Close()
	// reset deadline
	connection.SetDeadline(time.Time{})

	log.Println("Debug: secure session initialized")
	decryptor := server.getDecryptor(client_session)
	client_session.HandleSecureSession(decryptor)
}

// start listening connections from proxy
func (server *SServer) Start() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyPort()))
	if err != nil {
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
			continue
		}
		log.Printf("Info: new connection: %v\n", connection.RemoteAddr())
		go server.handleConnection(connection)
	}
}

/*
 initialize SecureSession with new connection
 read client_id, load public key for this client and initialize Secure Session
*/
func (server *SServer) initCommandsSSession(connection net.Conn) (*ClientCommandsSession, error) {
	client_id, err := ReadData(connection)
	if err != nil {
		return nil, err
	}
	client_session, err := NewClientCommandsSession(client_id, server.config, connection)
	if err != nil {
		return nil, err
	}
	ssession, err := session.New(server.config.GetServerId(), client_session.server_private_key, client_session)
	if err != nil {
		return nil, err
	}
	client_session.session = ssession
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
			return client_session, nil
		}

		err = SendData(buf, connection)
		if err != nil {
			return nil, err
		}

		if ssession.GetState() == session.STATE_ESTABLISHED {
			return client_session, err
		}
	}
}

/*
handle new connection by iniailizing secure session, starting proxy request
to db and decrypting responses from db
*/
func (server *SServer) handleCommandsConnection(connection net.Conn) {
	// initialization of session should be fast, so limit time for connection activity interval
	connection.SetDeadline(time.Now().Add(INIT_SSESSION_TIMEOUT))
	client_session, err := server.initCommandsSSession(connection)
	if err != nil {
		log.Println("Error: ", err)
		return
	}
	defer client_session.session.Close()
	// reset deadline
	connection.SetDeadline(time.Time{})
	log.Println("Debug: http api secure session initialized")
	client_session.HandleSession()
}

// start listening commands connections from proxy
func (server *SServer) StartCommands() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.config.GetProxyHost(), server.config.GetProxyCommandsPort()))
	if err != nil {
		return
	}
	log.Printf("Info: start listening %v:%v\n", server.config.GetProxyHost(), server.config.GetProxyCommandsPort())
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("Error: %v\n", ErrorMessage(fmt.Sprintf("can't accept new connection (%v)", connection.RemoteAddr()), err))
			continue
		}
		log.Printf("Info: new connection to http api: %v\n", connection.RemoteAddr())
		go server.handleCommandsConnection(connection)
	}
}
