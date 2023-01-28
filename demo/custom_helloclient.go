package demo

import (
	"fmt"
	"net"

	"github.com/lihongbin99/btls"
)

func CustonHelloClient(hostname string, port int) {
	addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", hostname, port))
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		panic(err)
	}

	tlsConn := btls.Client(conn, "")
	// 自定义 Hello Client
	paddingData := make([]byte, 215-len(hostname))
	tlsConn.ClientHello = &btls.HandshakeClientHello{
		TLSVersion: btls.TLS1_2,
		CipherSuite: []btls.Cipher_Suite{
			btls.Cipher_Suite(btls.GREASE),
			btls.TLS_AES_128_GCM_SHA256,
			btls.TLS_AES_256_GCM_SHA384,
			btls.TLS_CHACHA20_POLY1305_SHA256,
			btls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			btls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			btls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			btls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			btls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			btls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			btls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			btls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			btls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			btls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			btls.TLS_RSA_WITH_AES_128_CBC_SHA,
			btls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethod: []byte{0},
		Extensions: []btls.Extension{
			&btls.ExtensionGREASE{},
			&btls.ExtensionServerName{
				ServerNameList: []btls.ServerName{
					{
						ServerNameType: btls.SERVER_NAME_HOST_NAME,
						ServerName:     hostname,
					},
				},
			},
			&btls.ExtensionExtendedMasterSecret{},
			&btls.ExtendedRenegotiationInfo{},
			&btls.ExtensionSupportedGroups{
				SupportedGroups: []btls.GROUP_TYPE{
					btls.GROUP_TYPE(btls.GREASE),
					btls.GROUP_X25519,
					btls.GROUP_SECP256R1,
					btls.GROUP_SECP384R1,
				},
			},
			&btls.ExtensionEcPointFormats{
				ECPointFormats: []btls.EC_POINT_FORMAT_TYPE{
					btls.EC_POINT_FORMAT_UNCOMPRESSED,
				},
			},
			&btls.ExtensionSessionTicket{},
			&btls.ExtensionAppclicationLayerProtocol{
				ALPNProtocols: []btls.ALPNProtocol{
					{ALPNNextProtocol: "h2"},
					{ALPNNextProtocol: "http/1.1"},
				},
			},
			&btls.ExtensionStatusRequest{
				CertificateStatusType: btls.CERTIFICATE_STATUS_OCSP,
			},
			&btls.ExtensionSignatureAlgorithms{
				SignatureHashAlgorithms: []btls.SIGNATURE_ALGORITHM{
					btls.Ecdsa_secp256r1_sha256,
					btls.Rsa_pss_rsae_sha256,
					btls.Rsa_pkcs1_sha256,
					btls.Ecdsa_secp384r1_sha384,
					btls.Rsa_pss_rsae_sha384,
					btls.Rsa_pkcs1_sha384,
					btls.Rsa_pss_rsae_sha512,
					btls.Rsa_pkcs1_sha512,
				},
			},
			&btls.ExtensionSignedCertificateTimestamp{},
			&btls.ExtensionKeyShare{
				KeyShareEntrys: []btls.KeyShareEntry{
					{Group: btls.GROUP_TYPE(btls.GREASE)},
					{Group: btls.GROUP_X25519},
				},
			},
			&btls.ExtensionPskKeyExchangeModes{
				PSKKeyExchangeMode: []btls.PSK_KEY_EXCHANGE_MODE{
					btls.PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE,
				},
			},
			&btls.ExtensionSupportedVersion{
				SupportedVersions: []btls.TLS_VERSION{
					btls.TLS_VERSION(btls.GREASE),
					btls.TLS1_3,
					btls.TLS1_2,
				},
			},
			&btls.ExtensionCompressCertificate{
				Algorithms: []btls.COMPRESS_ALGORITHM{
					btls.COMPRESS_ALGORITHM_BROTLI,
				},
			},
			&btls.ExtensionApplicationSettings{
				SupportedALPNList: []btls.SupportedALPN{
					{SupportedALPN: "h2"},
				},
			},
			&btls.ExtensionGREASE{
				Data: []byte{0},
			},
			&btls.ExtensionPadding{PaddingData: paddingData},
		},
	}

	httpUilt(tlsConn, hostname)
}
