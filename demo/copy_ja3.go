package demo

import (
	"fmt"
	"net"
	"os"

	"github.com/lihongbin99/btls"
	"github.com/lihongbin99/log"
)

func CopyJa3() {
	listenAddr, _ := net.ResolveTCPAddr("tcp", ":13520")
	listen, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		fmt.Println("Listen Error:", err)
		os.Exit(0)
	}
	log.Info("Server Start Success")
	for {
		conn, err := listen.AcceptTCP()
		if err != nil {
			break
		}
		go func() {
			tlsConn := btls.Server(conn)
			if err := tlsConn.HandShake(); err != nil {
				log.Error(err)
			}
		}()
	}
}
