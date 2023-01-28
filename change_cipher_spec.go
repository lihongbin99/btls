package btls

type ContentChangeCipherSpec struct {
	ChangeCipherSpecMessage byte
}

func (t *ContentChangeCipherSpec) isContent() {}

func (t *TLSConn) ParseContentChangeCipherSpec(changeCipherSpecData []byte) (*ContentChangeCipherSpec, error) {
	changeCipherSpecMessage := changeCipherSpecData[0]

	contentChangeCipherSpec := ContentChangeCipherSpec{
		ChangeCipherSpecMessage: changeCipherSpecMessage,
	}
	return &contentChangeCipherSpec, nil
}
