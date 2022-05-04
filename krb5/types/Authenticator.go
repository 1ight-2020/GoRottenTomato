package types

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/flags"
	"fmt"
	"time"
)

type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int64             `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

func NewAuthenticator(realm string, cname PrincipalName) Authenticator {
	seq := funcs.GetNonce()
	now := time.Now().UTC()
	return Authenticator{
		AVNO: flags.PVNO,
		CRealm: realm,
		CName: cname,
		Cksum: Checksum{},
		Cusec: int((now.UnixNano() / int64(time.Microsecond)) - (now.Unix() * 1e6)),
		CTime: now,
		SeqNumber: int64(seq),
	}
}

func (org *Authenticator)Marshal() ([]byte, error) {
	data, err := asn1.Marshal(*org)
	if err != nil {
		return nil, fmt.Errorf("marshaling Authenticator failed %v", err)
	}
	data = funcs.AddASNTag(data, flags.Authenticator)
	return data, nil
}

