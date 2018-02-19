package network

import (
	"log"
	"net"
)

func Proxy(connFrom, connTo net.Conn, errCh chan<- error) {
	buf := make([]byte, 8192)
	for {
		log.Println("read from conn")
		n, err := connFrom.Read(buf)
		if err != nil{
			log.Println("Error: proxy err", err)
			errCh <- err
			return
		}
		if n == 0 {
			log.Println("Warning: read 0 bytes")
			continue
		}
		for nTo:=0; nTo < n; {
			log.Println("write to conn")
			nn, err := connTo.Write(buf[nTo:n])
			nTo += nn
			if err != nil{
				log.Println("can't write ", err)
				errCh <- err
				return
			}
		}
		log.Printf("proxied %v bytes\n", n)
	}
}