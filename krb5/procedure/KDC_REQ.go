package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"time"
)

type KDC_REQ_BODY struct {
	KDC_Options            asn1.BitString      `asn1:"explicit,tag:0"`
	CName                  types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm                  string              `asn1:"generalstring,explicit,tag:2"`
	SName                  types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From                   time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till                   time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime                  time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce                  int                 `asn1:"explicit,tag:7"`
	EType                  []int32             `asn1:"explicit,tag:8"`
	Addresses              []types.HostAddress `asn1:"explicit,optional,tag:9"`
	Enc_Authorization_Data types.EncryptedData `asn1:"explicit,optional,tag:10"`
	Additional_Tickets     []ticket.Ticket     `asn1:"explicit,optional,tag:11"`
}

type KDC_REQ struct {
	Pvno     int
	Msg_Type int
	Padata   types.PADataSequence
	Req_Body KDC_REQ_BODY
}

type mKDC_REQ struct {
	Pvno     int                  `asn1:"explicit,tag:1"`
	Msg_Type int                  `asn1:"explicit,tag:2"`
	Padata   types.PADataSequence `asn1:"explicit,optional,tag:3"`
	Req_Body asn1.RawValue         `asn1:"explicit,tag:4"`
}

type mKDC_REQ_BODY struct {
	KDC_Options            asn1.BitString      `asn1:"explicit,tag:0"`
	CName                  types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm                  string              `asn1:"generalstring,explicit,tag:2"`
	SName                  types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From                   time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till                   time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime                  time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce                  int                 `asn1:"explicit,tag:7"`
	EType                  []int32             `asn1:"explicit,tag:8"`
	Addresses              []types.HostAddress `asn1:"explicit,optional,tag:9"`
	Enc_Authorization_Data types.EncryptedData `asn1:"explicit,optional,tag:10"`
	Additional_Tickets     asn1.RawValue       `asn1:"explicit,optional,tag:11"`
}
