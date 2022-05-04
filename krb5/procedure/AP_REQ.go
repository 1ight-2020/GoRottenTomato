package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
)

type AP_REQ struct {
	PVNO                   int                 `asn1:"explicit,tag:0"`
	Msg_Type               int                 `asn1:"explicit,tag:1"`
	AP_Options             asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket                 ticket.Ticket       `asn1:"explicit,tag:3"`
	EncryptedAuthenticator types.EncryptedData `asn1:"explicit,tag:4"`
	Authenticator          types.Authenticator `asn1:"optional"`
}

type mAP_REQ struct {
	PVNO                   int                 `asn1:"explicit,tag:0"`
	MsgType                int                 `asn1:"explicit,tag:1"`
	APOptions              asn1.BitString      `asn1:"explicit,tag:2"`
	Ticket                 asn1.RawValue       `asn1:"explicit,tag:3"`
	EncryptedAuthenticator types.EncryptedData `asn1:"explicit,tag:4"`
}

func NewAPREQ(tgt ticket.Ticket, sessionkey types.EncryptionKey, auth types.Authenticator) (AP_REQ, error) {
	var apreq AP_REQ
	ap := types.NewKrbFlags()
	encauth, err := encAuthenticator(tgt, sessionkey, auth)
	if err != nil {
		return apreq, fmt.Errorf("build apreq failed %v", err)
	}
	apreq = AP_REQ{
		PVNO:                   flags.PVNO,
		Msg_Type:               flags.KRB_AP_REQ,
		AP_Options:             ap,
		Ticket:                 tgt,
		EncryptedAuthenticator: encauth,
	}
	return apreq, nil
}

func encAuthenticator(tgt ticket.Ticket, sessionkey types.EncryptionKey, auth types.Authenticator) (types.EncryptedData, error) {
	var encdata types.EncryptedData
	mauth, err := auth.Marshal()
	if err != nil {
		return encdata, fmt.Errorf("encrypt Authenticator failed %v", err)
	}
	usage := getKeyUsage(tgt.SName)
	encdata, err = crypto.GetEncryptedData(mauth, sessionkey, uint32(usage), tgt.Enc_Part.Kvno)
	if err != nil {
		return encdata, fmt.Errorf("encrypt Authenticator failed %v", err)
	}
	return encdata, nil
}

func getKeyUsage(pn types.PrincipalName) int {
	if pn.Name_String[0] == "krbtgt" {
		return flags.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR
	}
	return flags.AP_REQ_AUTHENTICATOR
}

func (org *AP_REQ)Marshal() ([]byte, error) {
	m := mAP_REQ{
		PVNO:                   org.PVNO,
		MsgType:                org.Msg_Type,
		APOptions:              org.AP_Options,
		EncryptedAuthenticator: org.EncryptedAuthenticator,
	}
	mticket, err := org.Ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("apreq marshaling failed %v", err)
	}
	m.Ticket = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        3,
		Bytes:      mticket,
	}
	data, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	data = funcs.AddASNTag(data, flags.APREQ)
	return data, nil
}