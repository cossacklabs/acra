// Package network contains network utils for establishing secure session, for listening connections.
//
package network

import (
	log "github.com/sirupsen/logrus"
	"net"
)

// Proxy reads data from connFrom, writes data to connTo
func Proxy(connFrom, connTo net.Conn, errCh chan<- error) {
	buf := make([]byte, 8192)
	for {
		n, err := connFrom.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if n == 0 {
			log.Warningln("read 0 bytes")
			continue
		}
		for nTo := 0; nTo < n; {
			nn, err := connTo.Write(buf[nTo:n])
			nTo += nn
			if err != nil {
				errCh <- err
				return
			}
		}
	}
}
