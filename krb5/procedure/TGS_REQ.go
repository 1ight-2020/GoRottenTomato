package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
	"time"
)

type TGS_REQ struct {
	KDC_REQ
}

func NewTGSREQ(kFlags asn1.BitString, realm string, cname, sname types.PrincipalName, till time.Time) *TGS_REQ {
	nonce := funcs.GetNonce()
	req := &TGS_REQ{
		KDC_REQ{
			Pvno:     flags.PVNO,
			Msg_Type: flags.KRB_TGS_REQ,
			Padata:   types.PADataSequence{},
			Req_Body: KDC_REQ_BODY{
				KDC_Options: kFlags,
				Realm:       realm,
				CName:       cname,
				SName:       sname,
				Till:        till,
				Nonce:       nonce,
				EType:       []int32{17, 18, 23},
			},
		},
	}
	return req
}

func (org *TGS_REQ)SetPAData(tgt ticket.Ticket, sessionkey types.EncryptionKey) error {
	data, err := org.Req_Body.Marshal()
	if err != nil {
		return fmt.Errorf("tgsreq failed %v", err)
	}
	eType := crypto.GetEType(sessionkey.KeyType)
	check, err := eType.GetChecksumHash(sessionkey.KeyValue, data, 6)
	if err != nil {
		return fmt.Errorf("tgsreq hash check failed")
	}

	auth := types.NewAuthenticator(tgt.Realm, org.Req_Body.CName)
	auth.Cksum = types.Checksum{
		CksumType: eType.GetHashID(),
		Checksum: check,
	}

	apreq, err := NewAPREQ(tgt, sessionkey, auth)
	if err != nil {
		return fmt.Errorf("tgsreq set padata failed %v", err)
	}
	mapreq, err := apreq.Marshal()
	if err != nil {
		return err
	}
	org.Padata = types.PADataSequence{
		types.PA_DATA{
			Padata_Type:  flags.PA_TGS_REQ,
			Padata_Value: mapreq,
		},
	}
	return nil
}

func (org *TGS_REQ)Marshal() ([]byte, error) {
	m := mKDC_REQ{
		Pvno:     org.Pvno,
		Msg_Type: org.Msg_Type,
		Padata:   org.Padata,
	}
	mrb, err := org.Req_Body.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tgsreq marshaling error %v", err)
	}
	m.Req_Body = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        4,
		Bytes:      mrb,
	}
	data, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	data = funcs.AddASNTag(data, flags.TGSREQ)
	return data, nil
}
