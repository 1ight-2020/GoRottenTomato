package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
	"time"
)

type KDC_REP struct {
	Pvno             int
	Msg_Type         int
	Padata           []types.PA_DATA
	CRealm           string
	CName            types.PrincipalName
	Ticket           ticket.Ticket
	Enc_Part         types.EncryptedData
	DecryptedEncPart EncKDCRepPart
}

type EncKDCRepPart struct {
	Key            types.EncryptionKey  `asn1:"explicit,tag:0"`
	Last_Reqs      []LastReq            `asn1:"explicit,tag:1"`
	Nonce          int                  `asn1:"explicit,tag:2"`
	Key_Expiration time.Time            `asn1:"generalized,explicit,optional,tag:3"`
	Flags          asn1.BitString       `asn1:"explicit,tag:4"`
	AuthTime       time.Time            `asn1:"generalized,explicit,tag:5"`
	StartTime      time.Time            `asn1:"generalized,explicit,optional,tag:6"`
	EndTime        time.Time            `asn1:"generalized,explicit,tag:7"`
	Renew_Till     time.Time            `asn1:"generalized,explicit,optional,tag:8"`
	SRealm         string               `asn1:"generalstring,explicit,tag:9"`
	SName          types.PrincipalName  `asn1:"explicit,tag:10"`
	CAddr          []types.HostAddress  `asn1:"explicit,optional,tag:11"`
	EncPAData      types.PADataSequence `asn1:"explicit,optional,tag:12"`
}

type LastReq struct {
	Lr_Type  int32     `asn1:"explicit,tag:0"`
	Lr_Value time.Time `asn1:"generalized,explicit,tag:1"`
}

type mKDC_REP struct {
	Pvno     int                  `asn1:"explicit,tag:0"`
	Msg_Type int                  `asn1:"explicit,tag:1"`
	Padata   types.PADataSequence `asn1:"explicit,optional,tag:2"`
	CRealm   string               `asn1:"generalstring,explicit,tag:3"`
	CName    types.PrincipalName  `asn1:"explicit,tag:4"`
	Ticket   asn1.RawValue        `asn1:"explicit,tag:5"`
	Enc_Part types.EncryptedData  `asn1:"explicit,tag:6"`
}

func (org *EncKDCRepPart)Unmarshal(data []byte) (err error) {
	_, err = asn1.UnmarshalWithParams(data, org, fmt.Sprintf("application,explicit,tag:%v", flags.EncASRepPart))
	if err != nil {
		_, err = asn1.UnmarshalWithParams(data, org, fmt.Sprintf("application,explicit,tag:%v", flags.EncTGSRepPart))
		if err != nil {
			return
		}
	}
	return 
}

func (org *EncKDCRepPart)GetKrbCredInfo() KrbCredInfo {
	return KrbCredInfo{
		Key:        org.Key,
		Flags:      org.Flags,
		StartTime:  org.StartTime,
		EndTime:    org.EndTime,
		Renew_Till: org.Renew_Till,
		SRealm:     org.SRealm,
		SName:      org.SName,
	}
}