package btls

import (
	"fmt"

	"github.com/lihongbin99/log"
	"golang.org/x/crypto/curve25519"
)

type Extension interface {
	isExtensions()
	ToBuf(conn *TLSConn) ([]byte, error)
}

type BaseExtension struct {
	ExtensionType   EXTENSION_TYPE
	ExtensionLength uint16
}

func (t *TLSConn) ParseExtension(extensionType EXTENSION_TYPE, extensionLength uint16, extensionData []byte) (Extension, error) {
	base := BaseExtension{
		ExtensionType:   extensionType,
		ExtensionLength: extensionLength,
	}

	if IsGREASE(uint16(extensionType)) {
		return t.ParseExtensionGREASE(base, extensionData)
	}
	// TODO  没有解析所有的 Extension
	switch extensionType {
	case EXTENSION_SERVER_NAME:
		return t.ParseExtensionServerName(base, extensionData)
	case EXTENSION_STATUS_REQUEST:
		return t.ParseExtensionStatusRequest(base, extensionData)
	case EXTENSION_SUPPORTED_GROUPS:
		return t.ParseExtensionSupportedGroups(base, extensionData)
	case EXTENSION_EC_POINT_FORMATS:
		return t.ParseExtensionEcPointFormats(base, extensionData)
	case EXTENSION_SIGNATURE_ALGORITHMS:
		return t.ParseExtensionSignatureAlgorithms(base, extensionData)
	case EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
		return t.ParseExtensionAppclicationLayerProtocol(base, extensionData)
	case EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP:
		return t.ParseExtensionSignedCertificateTimestamp(base, extensionData)
	case EXTENSION_PADDING:
		return t.ParseExtensionPadding(base, extensionData)
	case EXTENSION_EXTENDED_MASTER_SECRET:
		return t.ParseExtensionExtendedMasterSecret(base, extensionData)
	case EXTENSION_COMPRESS_CERTIFICATE:
		return t.ParseExtensionCompressCertificate(base, extensionData)
	case EXTENSION_SESSION_TICKET:
		return t.ParseExtensionSessionTicket(base, extensionData)
	case EXTENSION_PRE_SHARED_KEY:
		return t.ParseExtensionPreSharedKey(base, extensionData)
	case EXTENSION_SUPPORTED_VERSIONS:
		return t.ParseExtensionSupportedVersion(base, extensionData)
	case EXTENSION_PSK_KEY_EXCHANGE_MODES:
		return t.ParseExtensionPskKeyExchangeModes(base, extensionData)
	case EXTENSION_KEY_SHARE:
		return t.ParseExtensionKeyShare(base, extensionData)
	case EXTENSION_APPLICATION_SETTINGS:
		return t.ParseExtensionApplicationSettings(base, extensionData)
	case EXTENSION_RENEGOTIATION_INFO:
		return t.ParseExtensionRenegotiationInfo(base, extensionData)
	}
	return nil, fmt.Errorf("not supported ExtensionType: %d", extensionType)
}

type ExtensionGREASE struct {
	BaseExtension
	Data []byte
}

func (t *ExtensionGREASE) isExtensions() {}

func (t *ExtensionGREASE) ToBuf(conn *TLSConn) ([]byte, error) {
	if !conn.hasUseExtensionGrease {
		t.ExtensionType = EXTENSION_TYPE(conn.greaseBuf[GREASE_EXTENSION1_INDEX])
		conn.hasUseExtensionGrease = true
	} else {
		t.ExtensionType = EXTENSION_TYPE(conn.greaseBuf[GREASE_EXTENSION2_INDEX])
	}
	if t.Data == nil {
		t.Data = make([]byte, 0)
	}
	buf := make([]byte, 4+len(t.Data))
	if len(t.Data) > 0 {
		copy(buf[4:], t.Data)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionGREASE(base BaseExtension, extensionData []byte) (*ExtensionGREASE, error) {
	data := make([]byte, base.ExtensionLength)
	copy(data, extensionData)
	extensionGREASE := ExtensionGREASE{
		BaseExtension: base,
		Data:          data,
	}
	log.Trace("ParseExtensionGREASE:", base.ExtensionType, "; len:", base.ExtensionLength)
	return &extensionGREASE, nil
}

type ExtensionServerName struct {
	BaseExtension
	// ServerNameListLength uint16
	ServerNameList []ServerName
}

type ServerName struct {
	ServerNameType SERVER_NAME_TYPE
	// ServerNameLength uint16
	ServerName string
}

func (t *ExtensionServerName) isExtensions() {}

func (t *ExtensionServerName) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SERVER_NAME
	if t.ServerNameList == nil {
		t.ServerNameList = make([]ServerName, 0)
	}
	buf := make([]byte, 6)
	for i := 0; i < len(t.ServerNameList); i++ {
		buf = append(buf, byte(t.ServerNameList[i].ServerNameType))
		buf = append(buf, Uint16toBuf(uint16(len(t.ServerNameList[i].ServerName)))...)
		buf = append(buf, []byte(t.ServerNameList[i].ServerName)...)
	}
	buf[4] = byte((len(buf) - 6) >> 8)
	buf[5] = byte(len(buf) - 6)
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionServerName(base BaseExtension, extensionData []byte) (*ExtensionServerName, error) {
	serverNameListLength := toUint16(extensionData)
	serverNameList := make([]ServerName, 0)
	parseServerNameLength := uint16(0)
	for parseServerNameLength < serverNameListLength {
		serverNameType := toUint8(extensionData[parseServerNameLength+2:])
		serverNameLength := toUint16(extensionData[parseServerNameLength+3:])
		serverName := string(extensionData[parseServerNameLength+5 : parseServerNameLength+serverNameLength+5])
		serverNameList = append(serverNameList, ServerName{
			ServerNameType: SERVER_NAME_TYPE(serverNameType),
			// ServerNameLength: serverNameLength,
			ServerName: serverName,
		})

		parseServerNameLength += uint16(serverNameLength) + 3
	}

	extensionServerName := ExtensionServerName{
		BaseExtension: base,
		// ServerNameListLength: serverNameListLength,
		ServerNameList: serverNameList,
	}
	log.Trace("ParseExtensionServerName:", serverNameList)
	return &extensionServerName, nil
}

type ExtensionStatusRequest struct {
	BaseExtension
	CertificateStatusType CERTIFICATE_STATUS_TYPE
	// ResponderIDListLength   uint16
	ResponderIDList []byte
	// RequestExtensionsLength uint16
	RequestExtensions []byte
}

func (t *ExtensionStatusRequest) isExtensions() {}

func (t *ExtensionStatusRequest) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_STATUS_REQUEST
	if t.ResponderIDList == nil {
		t.ResponderIDList = make([]byte, 0)
	}
	if t.RequestExtensions == nil {
		t.RequestExtensions = make([]byte, 0)
	}
	buf := make([]byte, 9+len(t.ResponderIDList)+len(t.RequestExtensions))
	buf[4] = byte(t.CertificateStatusType)
	buf[5] = byte(len(t.ResponderIDList) >> 8)
	buf[6] = byte(len(t.ResponderIDList))
	if len(t.ResponderIDList) > 0 {
		copy(buf[7:], t.ResponderIDList)
	}
	buf[7+len(t.ResponderIDList)] = byte(len(t.RequestExtensions) >> 8)
	buf[8+len(t.ResponderIDList)] = byte(len(t.RequestExtensions))
	if len(t.RequestExtensions) > 0 {
		copy(buf[9+len(t.ResponderIDList):], t.RequestExtensions)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionStatusRequest(base BaseExtension, extensionData []byte) (*ExtensionStatusRequest, error) {
	certificateStatusType := toUint8(extensionData)
	responderIDListLength := toUint16(extensionData[1:])
	responderIDList := make([]byte, responderIDListLength)
	copy(responderIDList, extensionData[3:])
	requestExtensionsLength := toUint16(extensionData[responderIDListLength+3:])
	requestExtensions := make([]byte, requestExtensionsLength)
	copy(requestExtensions, extensionData[responderIDListLength+5:])

	extensionStatusRequest := ExtensionStatusRequest{
		BaseExtension:         base,
		CertificateStatusType: CERTIFICATE_STATUS_TYPE(certificateStatusType),
		// ResponderIDListLength:   responderIDListLength,
		ResponderIDList: responderIDList,
		// RequestExtensionsLength: requestExtensionsLength,
		RequestExtensions: requestExtensions,
	}
	log.Trace("ParseExtensionStatusRequest:", certificateStatusType, "; ResponderIDList:", responderIDList, "; RequestExtensions:", requestExtensions)
	return &extensionStatusRequest, nil
}

type ExtensionSupportedGroups struct {
	BaseExtension
	// SupportedGroupsListLength uint16
	SupportedGroups []GROUP_TYPE
}

func (t *ExtensionSupportedGroups) isExtensions() {}

func (t *ExtensionSupportedGroups) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SUPPORTED_GROUPS
	if t.SupportedGroups == nil {
		t.SupportedGroups = make([]GROUP_TYPE, 0)
	}
	buf := make([]byte, 6+len(t.SupportedGroups)*2)
	buf[4] = byte((len(t.SupportedGroups) * 2) >> 8)
	buf[5] = byte(len(t.SupportedGroups) * 2)
	for i := 0; i < len(t.SupportedGroups); i++ {
		if IsGREASE(uint16(t.SupportedGroups[i])) {
			t.SupportedGroups[i] = GROUP_TYPE(conn.greaseBuf[GREASE_GROUP_INDEX])
		}
		buf[i*2+6] = byte(t.SupportedGroups[i] >> 8)
		buf[i*2+6+1] = byte(t.SupportedGroups[i])
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionSupportedGroups(base BaseExtension, extensionData []byte) (*ExtensionSupportedGroups, error) {
	supportedGroupsListLength := toUint16(extensionData)
	supportedGroups := make([]GROUP_TYPE, supportedGroupsListLength/2)
	for i := uint16(0); i < supportedGroupsListLength/2; i++ {
		supportedGroups[i] = GROUP_TYPE(toUint16(extensionData[i*2+2:]))
	}
	extensionSupportedGroups := ExtensionSupportedGroups{
		BaseExtension: base,
		// SupportedGroupsListLength: supportedGroupsListLength,
		SupportedGroups: supportedGroups,
	}
	log.Trace("ParseExtensionSupportedGroups:", supportedGroups)
	return &extensionSupportedGroups, nil
}

type ExtensionEcPointFormats struct {
	BaseExtension
	// ECPointFormatsLength uint8
	ECPointFormats []EC_POINT_FORMAT_TYPE
}

func (t *ExtensionEcPointFormats) isExtensions() {}

func (t *ExtensionEcPointFormats) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_EC_POINT_FORMATS
	if t.ECPointFormats == nil {
		t.ECPointFormats = make([]EC_POINT_FORMAT_TYPE, 0)
	}
	buf := make([]byte, 5+len(t.ECPointFormats))
	buf[4] = byte(len(t.ECPointFormats))
	for i := 0; i < len(t.ECPointFormats); i++ {
		buf[i+5] = byte(t.ECPointFormats[i])
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionEcPointFormats(base BaseExtension, extensionData []byte) (*ExtensionEcPointFormats, error) {
	ECPointFormatsLength := toUint8(extensionData)
	ECPointFormats := make([]EC_POINT_FORMAT_TYPE, ECPointFormatsLength)
	for i := uint8(0); i < ECPointFormatsLength; i++ {
		ECPointFormats[i] = EC_POINT_FORMAT_TYPE(toUint8(extensionData[i+1:]))
	}
	extensionEcPointFormats := ExtensionEcPointFormats{
		BaseExtension: base,
		// ECPointFormatsLength: ECPointFormatsLength,
		ECPointFormats: ECPointFormats,
	}
	log.Trace("ParseExtensionEcPointFormats:", ECPointFormats)
	return &extensionEcPointFormats, nil
}

type ExtensionSignatureAlgorithms struct {
	BaseExtension
	// SignatureHashAlgorithmsLength uint16
	SignatureHashAlgorithms []SIGNATURE_ALGORITHM
}

func (t *ExtensionSignatureAlgorithms) isExtensions() {}

func (t *ExtensionSignatureAlgorithms) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SIGNATURE_ALGORITHMS
	if t.SignatureHashAlgorithms == nil {
		t.SignatureHashAlgorithms = make([]SIGNATURE_ALGORITHM, 0)
	}
	buf := make([]byte, 6+len(t.SignatureHashAlgorithms)*2)
	buf[4] = byte((len(t.SignatureHashAlgorithms) * 2) >> 8)
	buf[5] = byte(len(t.SignatureHashAlgorithms) * 2)
	for i := 0; i < len(t.SignatureHashAlgorithms); i++ {
		buf[i*2+6] = byte(t.SignatureHashAlgorithms[i] >> 8)
		buf[i*2+6+1] = byte(t.SignatureHashAlgorithms[i])
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionSignatureAlgorithms(base BaseExtension, extensionData []byte) (*ExtensionSignatureAlgorithms, error) {
	signatureHashAlgorithmsLength := toUint16(extensionData)
	signatureHashAlgorithms := make([]SIGNATURE_ALGORITHM, signatureHashAlgorithmsLength/2)
	for i := uint16(0); i < signatureHashAlgorithmsLength/2; i++ {
		signatureHashAlgorithms[i] = SIGNATURE_ALGORITHM(toUint16(extensionData[i*2+2:]))
	}
	extensionSignatureAlgorithms := ExtensionSignatureAlgorithms{
		BaseExtension: base,
		// SignatureHashAlgorithmsLength: signatureHashAlgorithmsLength,
		SignatureHashAlgorithms: signatureHashAlgorithms,
	}
	log.Trace("ParseExtensionSignatureAlgorithms:", signatureHashAlgorithms)
	return &extensionSignatureAlgorithms, nil
}

type ExtensionAppclicationLayerProtocol struct {
	BaseExtension
	// ALPNExtensionLength uint16
	ALPNProtocols []ALPNProtocol
}

type ALPNProtocol struct {
	// ALPNStringLength uint8
	ALPNNextProtocol string
}

func (t *ExtensionAppclicationLayerProtocol) isExtensions() {}

func (t *ExtensionAppclicationLayerProtocol) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
	if t.ALPNProtocols == nil {
		t.ALPNProtocols = make([]ALPNProtocol, 0)
	}
	buf := make([]byte, 6)
	for i := 0; i < len(t.ALPNProtocols); i++ {
		buf = append(buf, byte(len(t.ALPNProtocols[i].ALPNNextProtocol)))
		buf = append(buf, []byte(t.ALPNProtocols[i].ALPNNextProtocol)...)
	}
	buf[4] = byte((len(buf) - 6) >> 8)
	buf[5] = byte(len(buf) - 6)
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionAppclicationLayerProtocol(base BaseExtension, extensionData []byte) (*ExtensionAppclicationLayerProtocol, error) {
	ALPNExtensionLength := toUint16(extensionData)
	ALPNProtocols := make([]ALPNProtocol, 0)
	ParseALPNProtocolsLength := uint16(0)
	for ParseALPNProtocolsLength < ALPNExtensionLength {
		ALPNStringLength := toUint8(extensionData[ParseALPNProtocolsLength+2:])
		ALPNNextProtocol := string(extensionData[ParseALPNProtocolsLength+3 : ParseALPNProtocolsLength+3+uint16(ALPNStringLength)])
		ALPNProtocols = append(ALPNProtocols, ALPNProtocol{
			// ALPNStringLength: ALPNStringLength,
			ALPNNextProtocol: ALPNNextProtocol,
		})
		ParseALPNProtocolsLength += uint16(ALPNStringLength) + 1
	}

	extensionAppclicationLayerProtocol := ExtensionAppclicationLayerProtocol{
		BaseExtension: base,
		// ALPNExtensionLength: ALPNExtensionLength,
		ALPNProtocols: ALPNProtocols,
	}
	log.Trace("ParseExtensionAppclicationLayerProtocol:", ALPNProtocols)
	return &extensionAppclicationLayerProtocol, nil
}

type ExtensionSignedCertificateTimestamp struct {
	BaseExtension
	Data []byte
}

func (t *ExtensionSignedCertificateTimestamp) isExtensions() {}

func (t *ExtensionSignedCertificateTimestamp) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP
	if t.Data == nil {
		t.Data = make([]byte, 0)
	}
	buf := make([]byte, 4+len(t.Data))
	if len(t.Data) > 0 {
		copy(buf[4:], t.Data)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionSignedCertificateTimestamp(base BaseExtension, extensionData []byte) (*ExtensionSignedCertificateTimestamp, error) {
	data := make([]byte, base.ExtensionLength)
	copy(data, extensionData)
	extensionSignedCertificateTimestamp := ExtensionSignedCertificateTimestamp{
		BaseExtension: base,
		Data:          data,
	}
	log.Trace("ParseExtensionSignedCertificateTimestamp:", data)
	return &extensionSignedCertificateTimestamp, nil
}

type ExtensionPadding struct {
	BaseExtension
	PaddingData []byte
}

func (t *ExtensionPadding) isExtensions() {}

func (t *ExtensionPadding) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_PADDING
	if t.PaddingData == nil {
		t.PaddingData = make([]byte, 0)
	}
	buf := make([]byte, 4+len(t.PaddingData))
	if len(t.PaddingData) > 0 {
		copy(buf[4:], t.PaddingData)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionPadding(base BaseExtension, extensionData []byte) (*ExtensionPadding, error) {
	data := make([]byte, base.ExtensionLength)
	copy(data, extensionData)
	extensionPadding := ExtensionPadding{
		BaseExtension: base,
		PaddingData:   data,
	}
	log.Trace("ParseExtensionPadding:", data)
	return &extensionPadding, nil
}

type ExtensionExtendedMasterSecret struct {
	BaseExtension
	Data []byte
}

func (t *ExtensionExtendedMasterSecret) isExtensions() {}

func (t *ExtensionExtendedMasterSecret) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_EXTENDED_MASTER_SECRET
	if t.Data == nil {
		t.Data = make([]byte, 0)
	}
	buf := make([]byte, 4+len(t.Data))
	if len(t.Data) > 0 {
		copy(buf[4:], t.Data)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionExtendedMasterSecret(base BaseExtension, extensionData []byte) (*ExtensionExtendedMasterSecret, error) {
	data := make([]byte, base.ExtensionLength)
	copy(data, extensionData)
	extensionExtendedMasterSecret := ExtensionExtendedMasterSecret{
		BaseExtension: base,
		Data:          data,
	}
	log.Trace("ParseExtensionExtendedMasterSecret:", data)
	return &extensionExtendedMasterSecret, nil
}

type ExtensionCompressCertificate struct {
	BaseExtension
	// AlgorithmsLength uint8
	Algorithms []COMPRESS_ALGORITHM
}

func (t *ExtensionCompressCertificate) isExtensions() {}

func (t *ExtensionCompressCertificate) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_COMPRESS_CERTIFICATE
	if t.Algorithms == nil {
		t.Algorithms = make([]COMPRESS_ALGORITHM, 0)
	}
	buf := make([]byte, 5+len(t.Algorithms)*2)
	buf[4] = byte(len(t.Algorithms) * 2)
	for i := 0; i < len(t.Algorithms); i++ {
		buf[i*2+5] = byte(t.Algorithms[i] >> 8)
		buf[i*2+5+1] = byte(t.Algorithms[i])
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionCompressCertificate(base BaseExtension, extensionData []byte) (*ExtensionCompressCertificate, error) {
	algorithmsLength := toUint8(extensionData)
	algorithms := make([]COMPRESS_ALGORITHM, algorithmsLength/2)
	for i := uint8(0); i < algorithmsLength/2; i++ {
		algorithms[i] = COMPRESS_ALGORITHM(toUint16(extensionData[i*2+1:]))
	}
	extensionCompressCertificate := ExtensionCompressCertificate{
		BaseExtension: base,
		// AlgorithmsLength: algorithmsLength,
		Algorithms: algorithms,
	}
	log.Trace("ParseExtensionCompressCertificate:", algorithms)
	return &extensionCompressCertificate, nil
}

type ExtensionSessionTicket struct {
	BaseExtension
	Data []byte
}

func (t *ExtensionSessionTicket) isExtensions() {}

func (t *ExtensionSessionTicket) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SESSION_TICKET
	if t.Data == nil {
		t.Data = make([]byte, 0)
	}
	buf := make([]byte, 4+len(t.Data))
	if len(t.Data) > 0 {
		copy(buf[4:], t.Data)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionSessionTicket(base BaseExtension, extensionData []byte) (*ExtensionSessionTicket, error) {
	data := make([]byte, base.ExtensionLength)
	copy(data, extensionData)
	extensionSessionTicket := ExtensionSessionTicket{
		BaseExtension: base,
		Data:          data,
	}
	log.Trace("ParseExtensionSessionTicket:", data)
	return &extensionSessionTicket, nil
}

type ExtensionPreSharedKey struct {
	BaseExtension
	IdentitiesLength uint16
	PSKIdentity      PSKIdentity
	PSKBindersLength uint16
	PSKBinders       []byte
}

type PSKIdentity struct {
	IdentityLength      uint16
	Identity            []byte
	ObfuscatedTicketAge uint32
}

func (t *ExtensionPreSharedKey) isExtensions() {}

func (t *ExtensionPreSharedKey) ToBuf(conn *TLSConn) ([]byte, error) {
	buf := make([]byte, 8)
	buf[4] = byte((len(t.PSKIdentity.Identity) + 6) >> 8)
	buf[5] = byte(len(t.PSKIdentity.Identity) + 6)
	buf[6] = byte(len(t.PSKIdentity.Identity) >> 8)
	buf[7] = byte(len(t.PSKIdentity.Identity))
	buf = append(buf, t.PSKIdentity.Identity...)
	buf = append(buf, Uint32toBuf(t.PSKIdentity.ObfuscatedTicketAge)...)
	buf = append(buf, Uint16toBuf(uint16(len(t.PSKBinders)))...)
	buf = append(buf, t.PSKBinders...)
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionPreSharedKey(base BaseExtension, extensionData []byte) (*ExtensionPreSharedKey, error) {
	index := uint16(0)
	identitiesLength := toUint16(extensionData)
	index += 2
	identityLength := toUint16(extensionData[index:])
	index += 2
	identity := make([]byte, identityLength)
	copy(identity, extensionData[index:])
	index += uint16(identityLength)
	obfuscatedTicketAge := toUint32(extensionData[index:])
	index += 4
	pSKBindersLength := toUint16(extensionData[index:])
	pSKBinders := make([]byte, pSKBindersLength)
	copy(pSKBinders, extensionData[index:])

	extensionPreSharedKey := ExtensionPreSharedKey{
		BaseExtension:    base,
		IdentitiesLength: identitiesLength,
		PSKIdentity: PSKIdentity{
			IdentityLength:      identityLength,
			Identity:            identity,
			ObfuscatedTicketAge: obfuscatedTicketAge,
		},
		PSKBindersLength: pSKBindersLength,
		PSKBinders:       pSKBinders,
	}
	log.Trace("ParseExtensionPreSharedKey:", extensionPreSharedKey)
	return &extensionPreSharedKey, nil
}

type ExtensionSupportedVersion struct {
	BaseExtension
	// SupportedVersionsLength uint8
	SupportedVersions []TLS_VERSION
}

func (t *ExtensionSupportedVersion) isExtensions() {}

func (t *ExtensionSupportedVersion) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_SUPPORTED_VERSIONS
	if t.SupportedVersions == nil {
		t.SupportedVersions = make([]TLS_VERSION, 0)
	}
	buf := make([]byte, 5+len(t.SupportedVersions)*2)
	buf[4] = byte(len(t.SupportedVersions) * 2)
	for i := 0; i < len(t.SupportedVersions); i++ {
		tlsVersion := uint16(t.SupportedVersions[i])
		if IsGREASE(tlsVersion) {
			tlsVersion = conn.greaseBuf[GREASE_TLS_VERSION_INDEX]
		}
		buf[i*2+5] = byte(tlsVersion >> 8)
		buf[i*2+5+1] = byte(tlsVersion)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionSupportedVersion(base BaseExtension, extensionData []byte) (*ExtensionSupportedVersion, error) {
	index := uint8(0)
	supportedVersionsLength := uint8(2)
	if !t.isClient {
		supportedVersionsLength = toUint8(extensionData)
		index += 1
	}
	supportedVersions := make([]TLS_VERSION, supportedVersionsLength/2)
	for i := uint8(0); i < supportedVersionsLength/2; i++ {
		supportedVersions[i] = TLS_VERSION(toUint16(extensionData[i*2+index:]))
	}
	extensionSupportedVersion := ExtensionSupportedVersion{
		BaseExtension: base,
		// SupportedVersionsLength: supportedVersionsLength,
		SupportedVersions: supportedVersions,
	}
	log.Trace("ParseExtensionSupportedVersion:", supportedVersions)
	if t.isClient && len(supportedVersions) > 0 {
		t.TLSVersion = supportedVersions[0]
	}
	return &extensionSupportedVersion, nil
}

type ExtensionPskKeyExchangeModes struct {
	BaseExtension
	// PSKKeyExchangeModesLength uint8
	PSKKeyExchangeMode []PSK_KEY_EXCHANGE_MODE
}

func (t *ExtensionPskKeyExchangeModes) isExtensions() {}

func (t *ExtensionPskKeyExchangeModes) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_PSK_KEY_EXCHANGE_MODES
	if t.PSKKeyExchangeMode == nil {
		t.PSKKeyExchangeMode = make([]PSK_KEY_EXCHANGE_MODE, 0)
	}
	buf := make([]byte, 5+len(t.PSKKeyExchangeMode))
	buf[4] = byte(len(t.PSKKeyExchangeMode))
	for i := 0; i < len(t.PSKKeyExchangeMode); i++ {
		buf[i+5] = byte(t.PSKKeyExchangeMode[i])
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionPskKeyExchangeModes(base BaseExtension, extensionData []byte) (*ExtensionPskKeyExchangeModes, error) {
	PSKKeyExchangeModesLength := toUint8(extensionData)
	PSKKeyExchangeMode := make([]PSK_KEY_EXCHANGE_MODE, PSKKeyExchangeModesLength)
	for i := uint8(0); i < PSKKeyExchangeModesLength; i++ {
		PSKKeyExchangeMode[i] = PSK_KEY_EXCHANGE_MODE(toUint8(extensionData[i+1:]))
	}
	extensionPskKeyExchangeModes := ExtensionPskKeyExchangeModes{
		BaseExtension: base,
		// PSKKeyExchangeModesLength: PSKKeyExchangeModesLength,
		PSKKeyExchangeMode: PSKKeyExchangeMode,
	}
	log.Trace("ParseExtensionPskKeyExchangeModes:", PSKKeyExchangeMode)
	return &extensionPskKeyExchangeModes, nil
}

type ExtensionKeyShare struct {
	BaseExtension
	// ClientKeyShareLength uint16
	KeyShareEntrys []KeyShareEntry
}

type KeyShareEntry struct {
	Group GROUP_TYPE
	// KeyExchangeLength uint16
	KeyExchange []byte
}

func (t *ExtensionKeyShare) isExtensions() {}

func (t *ExtensionKeyShare) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_KEY_SHARE
	if t.KeyShareEntrys == nil {
		t.KeyShareEntrys = make([]KeyShareEntry, 0)
	}
	buf := make([]byte, 4)
	if len(t.KeyShareEntrys) > 0 {
		buf = append(buf, 0, 0)
	}
	for i := 0; i < len(t.KeyShareEntrys); i++ {
		if IsGREASE(uint16(t.KeyShareEntrys[i].Group)) {
			t.KeyShareEntrys[i].Group = GROUP_TYPE(conn.greaseBuf[GREASE_GROUP_INDEX])
			buf = append(buf, byte(t.KeyShareEntrys[i].Group>>8), byte(t.KeyShareEntrys[i].Group), 0, 1, 0)
		} else if t.KeyShareEntrys[i].Group == GROUP_X25519 {
			var err error = nil
			conn.PrivateKey = MakeRandomBuf(32)
			conn.PublicKey, err = curve25519.X25519(conn.PrivateKey, curve25519.Basepoint)
			if err != nil {
				return nil, err
			}
			t.KeyShareEntrys[i].KeyExchange = conn.PublicKey
			buf = append(buf,
				byte(t.KeyShareEntrys[i].Group>>8), byte(t.KeyShareEntrys[i].Group),
				byte(len(t.KeyShareEntrys[i].KeyExchange)>>8), byte(len(t.KeyShareEntrys[i].KeyExchange)),
			)
			buf = append(buf, t.KeyShareEntrys[i].KeyExchange...)
		} else {
			return nil, fmt.Errorf("not supported Group: %d", t.KeyShareEntrys[i].Group)
		}
	}
	if len(t.KeyShareEntrys) > 0 {
		buf[4] = byte((len(buf) - 6) >> 8)
		buf[5] = byte(len(buf) - 6)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionKeyShare(base BaseExtension, extensionData []byte) (*ExtensionKeyShare, error) {
	index := uint16(0)
	clientKeyShareLength := uint16(1)
	if !t.isClient {
		clientKeyShareLength = toUint16(extensionData)
		index += 2
	}
	keyShareEntrys := make([]KeyShareEntry, 0)
	parseKeyShareEntrysLength := uint16(0)
	for parseKeyShareEntrysLength < clientKeyShareLength {
		group := GROUP_TYPE(toUint16(extensionData[parseKeyShareEntrysLength+index:]))
		keyExchangeLength := toUint16(extensionData[parseKeyShareEntrysLength+index+2:])
		keyExchange := make([]byte, keyExchangeLength)
		copy(keyExchange, extensionData[parseKeyShareEntrysLength+index+4:])
		keyShareEntrys = append(keyShareEntrys, KeyShareEntry{
			Group: group,
			// KeyExchangeLength: keyExchangeLength,
			KeyExchange: keyExchange,
		})
		parseKeyShareEntrysLength += keyExchangeLength + 4
	}
	extensionKeyShare := ExtensionKeyShare{
		BaseExtension: base,
		// ClientKeyShareLength: clientKeyShareLength,
		KeyShareEntrys: keyShareEntrys,
	}
	log.Trace("ParseExtensionKeyShare:", keyShareEntrys)
	if t.isClient {
		// 计算主密钥
		if len(keyShareEntrys) == 0 {
			return nil, fmt.Errorf("ServerHello not KeyShare")
		}
		if keyShareEntrys[0].Group == GROUP_X25519 {
			var err error = nil
			t.PublicKey = keyShareEntrys[0].KeyExchange
			t.MasterKey, err = curve25519.X25519(t.PrivateKey, t.PublicKey)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("not supported Group: %d", keyShareEntrys[0].Group)
		}
	}
	return &extensionKeyShare, nil
}

type ExtensionApplicationSettings struct {
	BaseExtension
	// ALPSExtensionLength uint16
	SupportedALPNList []SupportedALPN
}

type SupportedALPN struct {
	// SupportedALPNLength uint8
	SupportedALPN string
}

func (t *ExtensionApplicationSettings) isExtensions() {}

func (t *ExtensionApplicationSettings) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_APPLICATION_SETTINGS
	if t.SupportedALPNList == nil {
		t.SupportedALPNList = make([]SupportedALPN, 0)
	}
	buf := make([]byte, 6)
	for i := 0; i < len(t.SupportedALPNList); i++ {
		buf = append(buf, byte(len(t.SupportedALPNList[i].SupportedALPN)))
		buf = append(buf, []byte(t.SupportedALPNList[i].SupportedALPN)...)
	}
	buf[4] = byte((len(buf) - 6) >> 8)
	buf[5] = byte(len(buf) - 6)
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionApplicationSettings(base BaseExtension, extensionData []byte) (*ExtensionApplicationSettings, error) {
	ALPSExtensionLength := toUint16(extensionData)
	SupportedALPNList := make([]SupportedALPN, 0)
	parseSupportedALPNListLength := uint16(0)
	for parseSupportedALPNListLength < ALPSExtensionLength {
		SupportedALPNLength := toUint8(extensionData[parseSupportedALPNListLength+2:])
		supportedALPN := string(extensionData[parseSupportedALPNListLength+3 : parseSupportedALPNListLength+3+uint16(SupportedALPNLength)])
		SupportedALPNList = append(SupportedALPNList, SupportedALPN{
			// SupportedALPNLength: SupportedALPNLength,
			SupportedALPN: supportedALPN,
		})
		parseSupportedALPNListLength += uint16(SupportedALPNLength) + 1
	}
	extensionApplicationSettings := ExtensionApplicationSettings{
		BaseExtension: base,
		// ALPSExtensionLength: ALPSExtensionLength,
		SupportedALPNList: SupportedALPNList,
	}
	log.Trace("ParseExtensionKeyShare:", SupportedALPNList)
	return &extensionApplicationSettings, nil
}

type ExtendedRenegotiationInfo struct {
	BaseExtension
	RenegotiationInfo RenegotiationInfo
}

type RenegotiationInfo struct {
	// RenegotiationInfoExtensionLength uint8
	Data []byte
}

func (t *ExtendedRenegotiationInfo) isExtensions() {}

func (t *ExtendedRenegotiationInfo) ToBuf(conn *TLSConn) ([]byte, error) {
	t.ExtensionType = EXTENSION_RENEGOTIATION_INFO
	if t.RenegotiationInfo.Data == nil {
		t.RenegotiationInfo.Data = make([]byte, 0)
	}
	buf := make([]byte, 5+len(t.RenegotiationInfo.Data))
	buf[4] = byte(len(t.RenegotiationInfo.Data))
	if len(t.RenegotiationInfo.Data) > 0 {
		copy(buf[4:], t.RenegotiationInfo.Data)
	}
	baseExtensionToBuf(t.ExtensionType, buf)
	return buf, nil
}

func (t *TLSConn) ParseExtensionRenegotiationInfo(base BaseExtension, extensionData []byte) (*ExtendedRenegotiationInfo, error) {
	renegotiationInfoExtensionLength := toUint8(extensionData)
	data := make([]byte, renegotiationInfoExtensionLength)
	copy(data, extensionData[1:])
	extendedRenegotiationInfo := ExtendedRenegotiationInfo{
		BaseExtension: base,
		RenegotiationInfo: RenegotiationInfo{
			// RenegotiationInfoExtensionLength: renegotiationInfoExtensionLength,
			Data: data,
		},
	}
	log.Trace("ParseExtensionRenegotiationInfo:", data)
	return &extendedRenegotiationInfo, nil
}

func baseExtensionToBuf(extensionType EXTENSION_TYPE, buf []byte) {
	buf[0] = byte(extensionType >> 8)
	buf[1] = byte(extensionType)
	buf[2] = byte((len(buf) - 4) >> 8)
	buf[3] = byte(len(buf) - 4)
}
