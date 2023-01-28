package btls

import (
	"net"
)

func Client(srcConn net.Conn, hostname string) *TLSConn {
	tlsConn := TLSConn{
		Conn:       srcConn,
		ServerName: hostname,
		isClient:   true,
	}
	return &tlsConn
}

func Server(srcConn net.Conn) *TLSConn {
	tlsConn := TLSConn{
		Conn:     srcConn,
		isClient: false,
	}
	return &tlsConn
}
