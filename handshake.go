package btls

import (
	"fmt"
	"math/rand"

	"github.com/lihongbin99/log"
)

type ContentHandshake struct {
	HandshakeType   HANDSHAKE_TYPE
	HandshakeLength uint24
	HandshakeImpl   HandshakeImpl
}

func (t *ContentHandshake) isContent() {}

type HandshakeImpl interface {
	isHandshakeImpl()
}

type HandshakeHelloRequest struct {
}

func (t *HandshakeHelloRequest) isHandshakeImpl() {}

type HandshakeClientHello struct {
	TLSVersion TLS_VERSION
	Random     []byte // len(32)
	// SessionIDLength         uint8
	SessionID []byte
	// CipherSuiteLength       uint16
	CipherSuite []Cipher_Suite
	// CompressionMethodLength uint8
	CompressionMethod []byte // [0]
	// ExtensionsLength  uint16
	Extensions []Extension
}

func (t *HandshakeClientHello) isHandshakeImpl() {}

type HandshakeServerHello struct {
	TLSVersion TLS_VERSION
	Random     [32]byte
	// SessionIDLength         uint8
	SessionID         []byte
	CipherSuite       Cipher_Suite
	CompressionMethod byte
	// ExtensionsLength  uint16
	Extensions []Extension
}

func (t *HandshakeServerHello) isHandshakeImpl() {}

type HandshakeCertificate struct {
}

func (t *HandshakeCertificate) isHandshakeImpl() {}

type HandshakeServerKeyExchange struct {
}

func (t *HandshakeServerKeyExchange) isHandshakeImpl() {}

type HandshakeCertificateRequest struct {
}

func (t *HandshakeCertificateRequest) isHandshakeImpl() {}

type HandshakeServerHello_Done struct {
}

func (t *HandshakeServerHello_Done) isHandshakeImpl() {}

type HandshakeCertificateVerify struct {
}

func (t *HandshakeCertificateVerify) isHandshakeImpl() {}

type HandshakeClientKeyExchange struct {
}

func (t *HandshakeClientKeyExchange) isHandshakeImpl() {}

type HandshakeFinished struct {
}

func (t *HandshakeFinished) isHandshakeImpl() {}

type HandshakeCertificateStatus struct {
}

func (t *HandshakeCertificateStatus) isHandshakeImpl() {}

func (t *TLSConn) ParseContentHandshake(handshakeData []byte) (*ContentHandshake, error) {
	index := 0
	handshakeType := HANDSHAKE_TYPE(toUint8(handshakeData[index:]))
	index += 1
	handshakeLength := toUint24(handshakeData[index:])
	index += 3
	log.Trace("HandshakeType:", handshakeType, "; HandshakeLength:", handshakeLength)

	var handshakeImpl HandshakeImpl = nil
	var err error = nil

	// TODO 没有实现完所有的 HandshakeType
	switch handshakeType {
	case Handshake_Client_Hello:
		handshakeImpl, err = t.ParseHandshakeClientHello(handshakeData[index:])
	case Handshake_Server_Hello:
		handshakeImpl, err = t.ParseHandshakeServerHello(handshakeData[index:])
	}

	if err != nil {
		return nil, err
	}
	if handshakeImpl == nil {
		return nil, fmt.Errorf("not supported HandshakeType: %d", handshakeType)
	}

	handshake := ContentHandshake{
		HandshakeType:   handshakeType,
		HandshakeLength: handshakeLength,
		HandshakeImpl:   handshakeImpl,
	}
	return &handshake, nil
}

func (t *TLSConn) MakeClientHelloBuf() error {
	if t.ClientHello == nil {
		paddingData := make([]byte, 215-len(t.ServerName))
		t.ClientHello = &HandshakeClientHello{
			TLSVersion: TLS1_2,
			CipherSuite: []Cipher_Suite{
				Cipher_Suite(GREASE),
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethod: []byte{0},
			Extensions: []Extension{
				&ExtensionGREASE{},
				&ExtensionServerName{
					ServerNameList: []ServerName{
						{
							ServerNameType: SERVER_NAME_HOST_NAME,
							ServerName:     t.ServerName,
						},
					},
				},
				&ExtensionExtendedMasterSecret{},
				&ExtendedRenegotiationInfo{},
				&ExtensionSupportedGroups{
					SupportedGroups: []GROUP_TYPE{
						GROUP_TYPE(GREASE),
						GROUP_X25519,
						GROUP_SECP256R1,
						GROUP_SECP384R1,
					},
				},
				&ExtensionEcPointFormats{
					ECPointFormats: []EC_POINT_FORMAT_TYPE{
						EC_POINT_FORMAT_UNCOMPRESSED,
					},
				},
				&ExtensionSessionTicket{},
				&ExtensionAppclicationLayerProtocol{
					ALPNProtocols: []ALPNProtocol{
						{ALPNNextProtocol: "h2"},
						{ALPNNextProtocol: "http/1.1"},
					},
				},
				&ExtensionStatusRequest{
					CertificateStatusType: CERTIFICATE_STATUS_OCSP,
				},
				&ExtensionSignatureAlgorithms{
					SignatureHashAlgorithms: []SIGNATURE_ALGORITHM{
						Ecdsa_secp256r1_sha256,
						Rsa_pss_rsae_sha256,
						Rsa_pkcs1_sha256,
						Ecdsa_secp384r1_sha384,
						Rsa_pss_rsae_sha384,
						Rsa_pkcs1_sha384,
						Rsa_pss_rsae_sha512,
						Rsa_pkcs1_sha512,
					},
				},
				&ExtensionSignedCertificateTimestamp{},
				&ExtensionKeyShare{
					KeyShareEntrys: []KeyShareEntry{
						{Group: GROUP_TYPE(GREASE)},
						{Group: GROUP_X25519},
					},
				},
				&ExtensionPskKeyExchangeModes{
					PSKKeyExchangeMode: []PSK_KEY_EXCHANGE_MODE{
						PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE,
					},
				},
				&ExtensionSupportedVersion{
					SupportedVersions: []TLS_VERSION{
						TLS_VERSION(GREASE),
						TLS1_3,
						TLS1_2,
					},
				},
				&ExtensionCompressCertificate{
					Algorithms: []COMPRESS_ALGORITHM{
						COMPRESS_ALGORITHM_BROTLI,
					},
				},
				&ExtensionApplicationSettings{
					SupportedALPNList: []SupportedALPN{
						{SupportedALPN: "h2"},
					},
				},
				&ExtensionGREASE{
					Data: []byte{0},
				},
				&ExtensionPadding{PaddingData: paddingData},
			},
		}
	}

	if t.greaseBuf == nil {
		t.greaseBuf = make([]uint16, GREASE_LAST_INDEX)
		for i := 0; i < GREASE_LAST_INDEX; i++ {
			r := rand.Intn(0x10)
			n := uint16(0x0A0A)
			n |= uint16(r) << 12
			n |= uint16(r) << 4
			t.greaseBuf[i] = n
		}
	}

	t.ClientHelloBuf = make([]byte, 0)
	t.ClientHelloBuf = append(t.ClientHelloBuf, byte(Content_Handshake))

	t.ClientHelloBuf = append(t.ClientHelloBuf, Uint16toBuf(uint16(TLS1_0))...)

	contentLengthIndex := len(t.ClientHelloBuf)
	t.ClientHelloBuf = append(t.ClientHelloBuf, 0, 0)

	t.ClientHelloBuf = append(t.ClientHelloBuf, byte(Handshake_Client_Hello))

	handshakeLengthIndex := len(t.ClientHelloBuf)
	t.ClientHelloBuf = append(t.ClientHelloBuf, 0, 0, 0)

	t.ClientHelloBuf = append(t.ClientHelloBuf, Uint16toBuf(uint16(t.ClientHello.TLSVersion))...)

	if t.ClientHello.Random == nil {
		t.ClientHello.Random = MakeRandomBuf(32)
	}
	t.ClientHelloBuf = append(t.ClientHelloBuf, t.ClientHello.Random...)

	if t.ClientHello.SessionID == nil {
		t.ClientHello.SessionID = MakeRandomBuf(32)
	}
	t.ClientHelloBuf = append(t.ClientHelloBuf, byte(len(t.ClientHello.SessionID)))
	t.ClientHelloBuf = append(t.ClientHelloBuf, t.ClientHello.SessionID...)

	if t.ClientHello.CipherSuite != nil {
		t.ClientHelloBuf = append(t.ClientHelloBuf, Uint16toBuf(uint16(len(t.ClientHello.CipherSuite)*2))...)
		for i := 0; i < len(t.ClientHello.CipherSuite); i++ {
			if IsGREASE(uint16(t.ClientHello.CipherSuite[i])) {
				t.ClientHello.CipherSuite[i] = Cipher_Suite(t.greaseBuf[GREASE_CIPHER_INDEX])
			}
			t.ClientHelloBuf = append(t.ClientHelloBuf, Uint16toBuf(uint16(t.ClientHello.CipherSuite[i]))...)
		}
	} else {
		t.ClientHelloBuf = append(t.ClientHelloBuf, 0, 0)
	}

	if t.ClientHello.CompressionMethod != nil {
		t.ClientHelloBuf = append(t.ClientHelloBuf, byte(len(t.ClientHello.CompressionMethod)))
		t.ClientHelloBuf = append(t.ClientHelloBuf, t.ClientHello.CompressionMethod...)
	} else {
		t.ClientHelloBuf = append(t.ClientHelloBuf, 1, 0)
	}

	extensionsLengthIndex := len(t.ClientHelloBuf)
	t.ClientHelloBuf = append(t.ClientHelloBuf, 0, 0)

	if t.ClientHello.Extensions != nil {
		for i := 0; i < len(t.ClientHello.Extensions); i++ {
			extensionBuf, err := t.ClientHello.Extensions[i].ToBuf(t)
			if err != nil {
				return err
			}
			t.ClientHelloBuf = append(t.ClientHelloBuf, extensionBuf...)
		}
	}

	t.ClientHelloBuf[contentLengthIndex+0] = byte(len(t.ClientHelloBuf[contentLengthIndex+2:]) >> 8)
	t.ClientHelloBuf[contentLengthIndex+1] = byte(len(t.ClientHelloBuf[contentLengthIndex+2:]))

	t.ClientHelloBuf[handshakeLengthIndex+0] = byte(len(t.ClientHelloBuf[handshakeLengthIndex+3:]) >> 16)
	t.ClientHelloBuf[handshakeLengthIndex+1] = byte(len(t.ClientHelloBuf[handshakeLengthIndex+3:]) >> 8)
	t.ClientHelloBuf[handshakeLengthIndex+2] = byte(len(t.ClientHelloBuf[handshakeLengthIndex+3:]))

	t.ClientHelloBuf[extensionsLengthIndex+0] = byte(len(t.ClientHelloBuf[extensionsLengthIndex+2:]) >> 8)
	t.ClientHelloBuf[extensionsLengthIndex+1] = byte(len(t.ClientHelloBuf[extensionsLengthIndex+2:]))

	return nil
}

func (t *TLSConn) ParseHandshakeClientHello(clientHelloData []byte) (*HandshakeClientHello, error) {
	var index uint32 = 0
	tlsVersion := toUint16(clientHelloData[index:])
	index += 2

	var random [32]byte
	copy(random[:], clientHelloData[index:])
	index += 32

	sessionIDLength := toUint8(clientHelloData[index:])
	sessionID := make([]byte, sessionIDLength)
	copy(sessionID, clientHelloData[index+1:])
	index += uint32(sessionIDLength) + 1

	cipherSuiteLength := toUint16(clientHelloData[index:])
	cipherSuite := make([]Cipher_Suite, cipherSuiteLength/2)
	for i := uint32(0); i < uint32(cipherSuiteLength); i += 2 {
		cipherSuite[i/2] = Cipher_Suite(toUint16(clientHelloData[index+i+2:]))
	}
	index += uint32(cipherSuiteLength) + 2

	compressionMethodLength := toUint8(clientHelloData[index:])
	compressionMethod := make([]byte, compressionMethodLength)
	copy(compressionMethod, clientHelloData[index+1:])
	index += uint32(compressionMethodLength) + 1

	extensionsLength := toUint16(clientHelloData[index:])
	index += 2
	extensions := make([]Extension, 0)
	parseExtensionsLen := uint16(0)
	for parseExtensionsLen < extensionsLength {
		extensionType := EXTENSION_TYPE(toUint16(clientHelloData[index:]))
		extensionLength := toUint16(clientHelloData[index+2:])

		extension, err := t.ParseExtension(extensionType, extensionLength, clientHelloData[index+4:])
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)

		index += uint32(extensionLength) + 4
		parseExtensionsLen += extensionLength + 4
	}

	log.Trace("TLSVersion:", tlsVersion, "; Random:", random, "; SessionID:", sessionID, "; CipherSuite:", cipherSuite, "; CompressionMethod:", compressionMethod)

	clientHello := HandshakeClientHello{
		TLSVersion: TLS_VERSION(tlsVersion),
		Random:     random[:],
		// SessionIDLength:         sessionIDLength,
		SessionID: sessionID,
		// CipherSuiteLength:       cipherSuiteLength,
		CipherSuite: cipherSuite,
		// CompressionMethodLength: compressionMethodLength,
		CompressionMethod: compressionMethod,
		// ExtensionsLength:        extensionsLength,
		Extensions: extensions,
	}
	return &clientHello, nil
}

func (t *TLSConn) ParseHandshakeServerHello(serverHelloData []byte) (*HandshakeServerHello, error) {
	var index uint32 = 0
	tlsVersion := toUint16(serverHelloData[index:])
	index += 2

	var random [32]byte
	copy(random[:], serverHelloData[index:])
	index += 32

	sessionIDLength := toUint8(serverHelloData[index:])
	sessionID := make([]byte, sessionIDLength)
	copy(sessionID, serverHelloData[index+1:])
	index += uint32(sessionIDLength) + 1

	cipherSuite := Cipher_Suite(toUint16(serverHelloData[index:]))
	index += 2

	compressionMethod := serverHelloData[index]
	index += 1

	extensionsLength := toUint16(serverHelloData[index:])
	index += 2
	extensions := make([]Extension, 0)
	parseExtensionsLen := uint16(0)
	for parseExtensionsLen < extensionsLength {
		extensionType := EXTENSION_TYPE(toUint16(serverHelloData[index:]))
		extensionLength := toUint16(serverHelloData[index+2:])

		extension, err := t.ParseExtension(extensionType, extensionLength, serverHelloData[index+4:])
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)

		index += uint32(extensionLength) + 4
		parseExtensionsLen += extensionLength + 4
	}

	log.Trace("TLSVersion:", tlsVersion, "; Random:", random, "; SessionID:", sessionID, "; CipherSuite:", cipherSuite, "; CompressionMethod:", compressionMethod)

	serverHello := HandshakeServerHello{
		TLSVersion: TLS_VERSION(tlsVersion),
		Random:     random,
		// SessionIDLength:         sessionIDLength,
		SessionID: sessionID,
		// CipherSuiteLength:       cipherSuiteLength,
		CipherSuite: cipherSuite,
		// CompressionMethodLength: compressionMethodLength,
		CompressionMethod: compressionMethod,
		// ExtensionsLength:        extensionsLength,
		Extensions: extensions,
	}
	return &serverHello, nil
}
