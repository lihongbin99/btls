package btls

import (
	"fmt"

	"github.com/lihongbin99/log"
	"github.com/lihongbin99/utils"
)

type Content struct {
	ContentType CONTENT_TYPE
	TLSVersion  TLS_VERSION
	// ContentLength uint16
	ContentImpl ContentImpl
}

type ContentImpl interface {
	isContent()
}

func (t *TLSConn) ReadContent() (*Content, error) {
	contentInfoBuf := make([]byte, 5)
	if err := utils.ReadN(t.Conn, contentInfoBuf, 5); err != nil {
		return nil, err
	}

	contentType := CONTENT_TYPE(toUint8(contentInfoBuf[0:]))
	tlsVersion := toUint16(contentInfoBuf[1:])
	contentLength := toUint16(contentInfoBuf[3:])
	log.Trace("ContentType:", contentType, "; TLSVersion:", tlsVersion, "; ContentLength:", contentLength)

	// TODO 后续的操作完全信任 ContentLength 的长度没有错误
	contentData := make([]byte, contentLength)
	if err := utils.ReadN(t.Conn, contentData, int(contentLength)); err != nil {
		return nil, err
	}

	var contentImpl ContentImpl = nil
	var err error = nil

	switch contentType {
	case Content_Change_Cipher_Spec:
		contentImpl, err = t.ParseContentChangeCipherSpec(contentData)
	case Content_Alert:
		contentImpl, err = t.ParseContentAlert(contentData)
	case Content_Handshake:
		contentImpl, err = t.ParseContentHandshake(contentData)
	case Content_Application_Data:
		contentImpl, err = t.ParseContentApplicationData(contentData)
	}

	if err != nil {
		return nil, err
	}
	if contentImpl == nil {
		return nil, fmt.Errorf("not supported ContentType: %d", contentType)
	}

	content := Content{
		ContentType: contentType,
		TLSVersion:  TLS_VERSION(tlsVersion),
		// ContentLength: contentLength,
		ContentImpl: contentImpl,
	}
	return &content, nil
}
