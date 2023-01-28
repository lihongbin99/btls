package btls

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/lihongbin99/log"
)

type ContentApplicationData struct {
}

func (t *ContentApplicationData) isContent() {}

func (t *TLSConn) ParseContentApplicationData(applicationDataData []byte) (*ContentApplicationData, error) {
	log.Info("application data:", applicationDataData)
	switch t.ServerHello.CipherSuite {
	case TLS_AES_256_GCM_SHA384:
		// TOOD
	default:
		return nil, fmt.Errorf("not supported Cipher Suite: %d", t.ServerHello.CipherSuite)
	}
	return nil, fmt.Errorf("not supped application data")
}

func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	return aead
}
