package demo

import (
	"fmt"
	"net"

	"github.com/lihongbin99/btls"
)

func SimpleDemo(hostname string, port int) {
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", hostname, port))
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		panic(err)
	}

	// 只需增加一行代码
	tlsConn := btls.Client(conn, hostname)

	httpUilt(tlsConn, hostname)
}
