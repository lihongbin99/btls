package btls

import (
	"fmt"
	"net"
	"sync"

	"github.com/lihongbin99/log"
)

type TLSConn struct {
	net.Conn
	isClient   bool
	ServerName string

	tlsStatus     TLS_STATUS
	handshakeLock sync.Mutex

	TLSVersion TLS_VERSION

	ClientHello    *HandshakeClientHello
	ClientHelloBuf []byte
	ServerHello    *HandshakeServerHello
	ServerHelloBuf []byte

	PrivateKey []byte
	PublicKey  []byte
	MasterKey  []byte

	greaseBuf             []uint16
	hasUseExtensionGrease bool
}

func (t *TLSConn) HandShake() error {
	t.handshakeLock.Lock()
	defer t.handshakeLock.Unlock()
	var err error = nil
	if t.isClient {
		err = t.clientHandshake()
	} else {
		err = t.serverHandshake()
	}
	if err != nil {
		t.Close()
	}
	return err
}

func (t *TLSConn) clientHandshake() error {
	// 构建 Client Hello
	if err := t.MakeClientHelloBuf(); err != nil {
		return err
	}

	// 发送 Client Hello
	t.Conn.Write(t.ClientHelloBuf)

	// 接收 Server Hello
	content, err := t.ReadContent()
	if err != nil {
		return err
	}
	if content.ContentType == Content_Alert {
		alert := content.ContentImpl.(*ContentAlert)
		if alert.Level == ALERT_WARNING {
			log.Warn("Read Server Hello Warn:", alert.Description)
		} else if alert.Level == ALERT_FATAL {
			return fmt.Errorf("Read Server Hello Fatal: %d", alert.Description)
		}
	}

	// 解析 Server Hello
	if content.ContentType != Content_Handshake {
		return fmt.Errorf("not server handshake")
	}
	serverHandshake := content.ContentImpl.(*ContentHandshake)
	if serverHandshake.HandshakeType != Handshake_Server_Hello {
		return fmt.Errorf("not server hello")
	}
	serverHello := serverHandshake.HandshakeImpl.(*HandshakeServerHello)
	t.ServerHello = serverHello
	if t.TLSVersion == 0 {
		t.TLSVersion = t.ServerHello.TLSVersion
	}

	// 后续流程
	for {
		content, err = t.ReadContent()
		if err != nil {
			return err
		}
		if content.ContentType == Content_Change_Cipher_Spec {
			break
		}
		return fmt.Errorf("not server Change Cipher Spec")
	}

	// 后续流程2
	content, err = t.ReadContent()
	if err != nil {
		return err
	}

	return fmt.Errorf("not init handshake")
}

func (t *TLSConn) serverHandshake() error {
	// 接受 Client Hello
	_, err := t.ReadContent()
	if err != nil {
		return err
	}
	// 解析 Client Hello
	// 构建 Server Hello
	// 发送 Server Hello
	// 后续流程
	return nil
}

func (t *TLSConn) Read(buf []byte) (n int, err error) {
	if t.tlsStatus == TLS_ST_BEFORE {
		if err := t.HandShake(); err != nil {
			return 0, err
		}
	}
	// 增加解密代码
	return t.Conn.Read(buf)
}

func (t *TLSConn) Write(buf []byte) (n int, err error) {
	if t.tlsStatus == TLS_ST_BEFORE {
		if err := t.HandShake(); err != nil {
			return 0, err
		}
	}
	// TODO 增加加密代码
	return t.Conn.Write(buf)
}
