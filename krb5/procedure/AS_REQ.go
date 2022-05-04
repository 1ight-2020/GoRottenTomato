package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
	"time"
)

type AS_REQ struct {
	KDC_REQ
}

func NewASREQ(realm string, clientName,serverName types.PrincipalName, flag asn1.BitString, eTypeID int32) *AS_REQ {
	nonce := funcs.GetNonce()
	now := time.Now().UTC()
	req := &AS_REQ{
		KDC_REQ{
			Pvno:     flags.PVNO,
			Msg_Type: flags.KRB_AS_REQ,
			Padata:   types.PADataSequence{},
			Req_Body: KDC_REQ_BODY{
				KDC_Options: flag,
				CName:       clientName,
				Realm:       realm,
				SName:       serverName,
				Till:        now.Add(time.Hour * 24),
				Nonce:       nonce,
				EType:       []int32{eTypeID},
			},
		},
	}
	return req
}

func (org *KDC_REQ_BODY)Marshal() ([]byte, error) {
	marshal := mKDC_REQ_BODY{
		KDC_Options:            org.KDC_Options,
		CName:                  org.CName,
		Realm:                  org.Realm,
		SName:                  org.SName,
		From:                   org.From,
		Till:                   org.Till,
		RTime:                  org.RTime,
		Nonce:                  org.Nonce,
		EType:                  org.EType,
		Addresses:              org.Addresses,
		Enc_Authorization_Data: org.Enc_Authorization_Data,
	}

	raw, err := ticket.MarshalTicket(org.Additional_Tickets)
	if err != nil {
		return nil, fmt.Errorf("AS_REQ %v", err)
	}

	raw.Tag = 11

	if len(raw.Bytes) >0 {
		marshal.Additional_Tickets = raw
	}

	data, err := asn1.Marshal(marshal)
	if err != nil {
		return nil, fmt.Errorf("error in KDC_REQ_BODY %v", err)
	}

	return data, nil
}

func (org *AS_REQ)Marshal() ([]byte, error) {
	marshal := mKDC_REQ{
		Pvno:     org.Pvno,
		Msg_Type: org.Msg_Type,
		Padata:   org.Padata,
	}
	reqBody, err := org.Req_Body.Marshal()
	if err != nil {
		return nil, err
	}

	marshal.Req_Body = asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		IsCompound: true,
		Tag: 4,
		Bytes: reqBody,
	}
	
	data, err := asn1.Marshal(marshal)
	if err != nil {
		return nil, fmt.Errorf("error in AS_REQ %v", err)
	}
	data = funcs.AddASNTag(data, flags.AS_REQ)
	return data, nil
}

