package btls

type ContentAlert struct {
	Level       ALERT_LEVEL
	Description ALERT_DESCRIPTION
}

func (t *ContentAlert) isContent() {}

func (t *TLSConn) ParseContentAlert(alertData []byte) (*ContentAlert, error) {
	contentAlert := ContentAlert{
		Level:       ALERT_LEVEL(alertData[0]),
		Description: ALERT_DESCRIPTION(alertData[1]),
	}
	return &contentAlert, nil
}
