package network


import "net"

type ConnectionWrapper interface{
	WrapClient(id []byte, conn net.Conn)(net.Conn, error)
	WrapServer(id []byte, conn net.Conn)(net.Conn, error)
}