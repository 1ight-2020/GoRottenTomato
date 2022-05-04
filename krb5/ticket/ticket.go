package ticket

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/types"
	"time"
)

type Ticket struct {
	Tkt_VNO          int                 `asn1:"explicit,tag:0"`
	Realm            string              `asn1:"generalstring,explicit,tag:1"`
	SName            types.PrincipalName `asn1:"explicit,tag:2"`
	Enc_Part         types.EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart       `asn1:"optional"`
}

type EncTicketPart struct {
	Flags             asn1.BitString          `asn1:"explicit,tag:0"`
	Key               types.EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string                  `asn1:"generalstring,explicit,tag:2"`
	CName             types.PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding       `asn1:"explicit,tag:4"`
	AuthTime          time.Time               `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time               `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time               `asn1:"generalized,explicit,tag:7"`
	Renew_Till        time.Time               `asn1:"generalized,explicit,optional,tag:8"`
	Caddr             types.HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData types.AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	Tr_Type   int32  `asn1:"explicit,tag:0"`
	Contents  []byte `asn1:"explicit,tag:1"`
}

type SeqOfRawTickets []asn1.RawValue


