package btls

type TLS_STATUS uint8

const (
	TLS_ST_BEFORE TLS_STATUS = 0 // 必须是0, 因为使用了go的默认值
	TLS_ST_OK     TLS_STATUS = 1
)

var GREASE = uint16(0x0A0A) // [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]

const (
	GREASE_CIPHER_INDEX int = iota
	GREASE_GROUP_INDEX
	GREASE_EXTENSION1_INDEX
	GREASE_EXTENSION2_INDEX
	GREASE_TLS_VERSION_INDEX
	GREASE_LAST_INDEX
)

func IsGREASE(n uint16) bool {
	return (n & 0x0F0F) == 0x0A0A
}

type TLS_VERSION uint16

const (
	TLS1_0 TLS_VERSION = 0x0301 // 769
	TLS1_1 TLS_VERSION = 0x0302 // 770
	TLS1_2 TLS_VERSION = 0x0303 // 771
	TLS1_3 TLS_VERSION = 0x0304 // 772
)

type CONTENT_TYPE uint8

const (
	Content_Change_Cipher_Spec CONTENT_TYPE = 0x14 // 20
	Content_Alert              CONTENT_TYPE = 0x15 // 21
	Content_Handshake          CONTENT_TYPE = 0x16 // 22
	Content_Application_Data   CONTENT_TYPE = 0x17 // 23
)

type ALERT_LEVEL uint8

const (
	ALERT_WARNING ALERT_LEVEL = 1
	ALERT_FATAL   ALERT_LEVEL = 2
)

type ALERT_DESCRIPTION uint8

const (
	CLOSE_NOTIFY                ALERT_DESCRIPTION = 0
	UNEXPECTED_MESSAGE          ALERT_DESCRIPTION = 10
	BAD_RECORD_MAC              ALERT_DESCRIPTION = 20
	DECRYPTION_FAILED_RESERVED  ALERT_DESCRIPTION = 21
	RECORD_OVERFLOW             ALERT_DESCRIPTION = 22
	DECOMPRESSION_FAILURE       ALERT_DESCRIPTION = 30
	HANDSHAKE_FAILURE           ALERT_DESCRIPTION = 40
	NO_CERTIFICATE_RESERVED     ALERT_DESCRIPTION = 41
	BAD_CERTIFICATE             ALERT_DESCRIPTION = 42
	UNSUPPORTED_CERTIFICATE     ALERT_DESCRIPTION = 43
	CERTIFICATE_REVOKED         ALERT_DESCRIPTION = 44
	CERTIFICATE_EXPIRED         ALERT_DESCRIPTION = 45
	CERTIFICATE_UNKNOWN         ALERT_DESCRIPTION = 46
	ILLEGAL_PARAMETER           ALERT_DESCRIPTION = 47
	UNKNOWN_CA                  ALERT_DESCRIPTION = 48
	ACCESS_DENIED               ALERT_DESCRIPTION = 49
	DECODE_ERROR                ALERT_DESCRIPTION = 50
	DECRYPT_ERROR               ALERT_DESCRIPTION = 51
	EXPORT_RESTRICTION_RESERVED ALERT_DESCRIPTION = 60
	PROTOCOL_VERSION            ALERT_DESCRIPTION = 70
	INSUFFICIENT_SECURITY       ALERT_DESCRIPTION = 71
	INTERNAL_ERROR              ALERT_DESCRIPTION = 80
	USER_CANCELED               ALERT_DESCRIPTION = 90
	NO_RENEGOTIATION            ALERT_DESCRIPTION = 100
	UNSUPPORTED_EXTENSION       ALERT_DESCRIPTION = 110
)

type HANDSHAKE_TYPE uint8

const (
	Handshake_Hello_Request       HANDSHAKE_TYPE = 0x00 // 0
	Handshake_Client_Hello        HANDSHAKE_TYPE = 0x01 // 1
	Handshake_Server_Hello        HANDSHAKE_TYPE = 0x02 // 2
	Handshake_Certificate         HANDSHAKE_TYPE = 0x0B // 11
	Handshake_Server_Key_Exchange HANDSHAKE_TYPE = 0x0C // 12
	Handshake_Certificate_Request HANDSHAKE_TYPE = 0x0D // 13
	Handshake_Server_Hello_Done   HANDSHAKE_TYPE = 0x0E // 14
	Handshake_Certificate_Verify  HANDSHAKE_TYPE = 0x0F // 15
	Handshake_Client_Key_Exchange HANDSHAKE_TYPE = 0x10 // 16
	Handshake_Finished            HANDSHAKE_TYPE = 0x14 // 20
	Handshake_Certificate_Status  HANDSHAKE_TYPE = 0x16 // 22
)

type Cipher_Suite uint16

const (
	TLS_RSA_WITH_AES_128_CBC_SHA                  Cipher_Suite = 0x002F // 47
	TLS_RSA_WITH_AES_256_CBC_SHA                  Cipher_Suite = 0x0035 // 53
	TLS_RSA_WITH_AES_128_GCM_SHA256               Cipher_Suite = 0x009C // 156
	TLS_RSA_WITH_AES_256_GCM_SHA384               Cipher_Suite = 0x009D // 157
	TLS_AES_128_GCM_SHA256                        Cipher_Suite = 0x1301 // 4865
	TLS_AES_256_GCM_SHA384                        Cipher_Suite = 0x1302 // 4866
	TLS_CHACHA20_POLY1305_SHA256                  Cipher_Suite = 0x1303 // 4867
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            Cipher_Suite = 0xC013 // 49171
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            Cipher_Suite = 0xC014 // 49172
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       Cipher_Suite = 0xC02B // 49195
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       Cipher_Suite = 0xC02C // 49196
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         Cipher_Suite = 0xC02F // 49199
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         Cipher_Suite = 0xC030 // 49200
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   Cipher_Suite = 0xCCA8 // 52392
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 Cipher_Suite = 0xCCA9 // 52393
)

type EXTENSION_TYPE uint16

const (
	EXTENSION_SERVER_NAME                            EXTENSION_TYPE = 0x0000 // 0
	EXTENSION_STATUS_REQUEST                         EXTENSION_TYPE = 0x0005 // 5
	EXTENSION_SUPPORTED_GROUPS                       EXTENSION_TYPE = 0x000A // 10
	EXTENSION_EC_POINT_FORMATS                       EXTENSION_TYPE = 0x000B // 11
	EXTENSION_SIGNATURE_ALGORITHMS                   EXTENSION_TYPE = 0x000D // 13
	EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION EXTENSION_TYPE = 0x0010 // 16
	EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP           EXTENSION_TYPE = 0x0012 // 18
	EXTENSION_PADDING                                EXTENSION_TYPE = 0x0015 // 21
	EXTENSION_EXTENDED_MASTER_SECRET                 EXTENSION_TYPE = 0x0017 // 23
	EXTENSION_COMPRESS_CERTIFICATE                   EXTENSION_TYPE = 0x001B // 27
	EXTENSION_SESSION_TICKET                         EXTENSION_TYPE = 0x0023 // 35
	EXTENSION_PRE_SHARED_KEY                         EXTENSION_TYPE = 0x0029 // 41
	EXTENSION_SUPPORTED_VERSIONS                     EXTENSION_TYPE = 0x002B // 43
	EXTENSION_PSK_KEY_EXCHANGE_MODES                 EXTENSION_TYPE = 0x002D // 45
	EXTENSION_KEY_SHARE                              EXTENSION_TYPE = 0x0033 // 51
	EXTENSION_APPLICATION_SETTINGS                   EXTENSION_TYPE = 0x4469 // 17513
	EXTENSION_RENEGOTIATION_INFO                     EXTENSION_TYPE = 0xFF01 // 65281
)

type SERVER_NAME_TYPE uint8

const (
	SERVER_NAME_HOST_NAME SERVER_NAME_TYPE = 0
)

type GROUP_TYPE uint16

const (
	GROUP_X25519    GROUP_TYPE = 0x001D // 29
	GROUP_SECP256R1 GROUP_TYPE = 0x0017 // 23
	GROUP_SECP384R1 GROUP_TYPE = 0x0018 // 24
)

type EC_POINT_FORMAT_TYPE uint8

const (
	EC_POINT_FORMAT_UNCOMPRESSED EC_POINT_FORMAT_TYPE = 0
)

type CERTIFICATE_STATUS_TYPE uint8

const (
	CERTIFICATE_STATUS_OCSP CERTIFICATE_STATUS_TYPE = 1
)

type SIGNATURE_ALGORITHM uint16

const (
	Rsa_pkcs1_sha256       = 0x0401 // 1025
	Ecdsa_secp256r1_sha256 = 0x0403 // 1027
	Rsa_pkcs1_sha384       = 0x0501 // 1281
	Ecdsa_secp384r1_sha384 = 0x0503 // 1283
	Rsa_pkcs1_sha512       = 0x0601 // 1537
	Rsa_pss_rsae_sha256    = 0x0804 // 2052
	Rsa_pss_rsae_sha384    = 0x0805 // 2053
	Rsa_pss_rsae_sha512    = 0x0806 // 2054
)

type PSK_KEY_EXCHANGE_MODE uint8

const (
	PSK_KEY_EXCHANGE_MODE_PSK_KE     PSK_KEY_EXCHANGE_MODE = 0x00
	PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE PSK_KEY_EXCHANGE_MODE = 0x01
	PSK_KEY_EXCHANGE_MODE_PSK_RSA_KE PSK_KEY_EXCHANGE_MODE = 0x02
)

type COMPRESS_ALGORITHM uint16

const (
	COMPRESS_ALGORITHM_BROTLI COMPRESS_ALGORITHM = 0x0002
)
