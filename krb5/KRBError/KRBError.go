package KRBError

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/types"
	"fmt"
	"time"
)

type KRB_Error struct {
	Pvno       int                 `asn1:"explicit,tag:0"`
	Msg_Type   int                 `asn1:"explicit,tag:1"`
	CTime      time.Time           `asn1:"generalized,optional,explicit,tag:2"`
	Cusec      int                 `asn1:"optional,explicit,tag:3"`
	STime      time.Time           `asn1:"generalized,explicit,tag:4"`
	Susec      int                 `asn1:"explicit,tag:5"`
	Error_Code int32               `asn1:"explicit,tag:6"`
	CRealm     string              `asn1:"generalstring,optional,explicit,tag:7"`
	CName      types.PrincipalName `asn1:"optional,explicit,tag:8"`
	Realm      string              `asn1:"generalstring,explicit,tag:9"`
	SName      types.PrincipalName `asn1:"explicit,tag:10"`
	E_Text     string              `asn1:"generalstring,optional,explicit,tag:11"`
	E_Data     []byte              `asn1:"optional,explicit,tag:12"`
}

func (k *KRB_Error)Unmarshal(data []byte) error {
	_, err := asn1.UnmarshalWithParams(data, k, fmt.Sprintf("application,explicit,tag:%v", flags.KRBError))
	if err != nil {
		return Errorf(err, EncodingError, "KRB_ERROR unmarshal error")
	}
	expectedMsgType := flags.KRB_ERROR
	if k.Msg_Type != expectedMsgType {
		return NewErrorf(KRBMsgError, "message ID does not indicate a KRB_ERROR. Expected: %v; Actual: %v", expectedMsgType, k.Msg_Type)
	}
	return nil
}

func (k KRB_Error)Error() string {
	etxt := fmt.Sprintf("KRB Error %s ", Lookup(k.Error_Code))
	if k.E_Text != "" {
		etxt = fmt.Sprintf("%s - %s", etxt, k.E_Text)
	}
	return etxt
}

func ProcessUnmarshalReplyError(b []byte, err error) error {
	switch err.(type) {
	case asn1.StructuralError:
		var krberr KRB_Error
		tmperr := krberr.Unmarshal(b)
		if tmperr != nil {
			return Errorf(err, EncodingError, "failed to unmarshal KDC's reply")
		}
		return krberr
	default:
		return Errorf(err, EncodingError, "failed to unmarshal KDC's reply")
	}
}