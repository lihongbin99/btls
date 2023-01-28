package demo

import (
	"fmt"
	"io"
	"net"
)

func httpUilt(conn net.Conn, hostname string) {
	request := make([]byte, 0)
	request = append(request, []byte("GET / HTTP/1.1\r\n")...)
	request = append(request, []byte("Host: "+hostname+"\r\n")...) // TODO 百度不能用
	request = append(request, []byte("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76\r\n")...)
	request = append(request, []byte("\r\n")...)
	if _, err := conn.Write(request); err != nil {
		panic(err)
	}

	response := make([]byte, 64*1024)
	for {
		readLen, err := conn.Read(response)
		if err != nil {
			if err != io.EOF {
				panic(err)
			}
			break
		}
		fmt.Println(string(response[:readLen]))
	}

	conn.Close()
}
