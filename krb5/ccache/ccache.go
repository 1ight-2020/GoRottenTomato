package ccache

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/types"
	"time"
)

type principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

type header struct {
	length uint16
	fields []headerField
}

type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal principal
	Credentials      []*Credential
	Path             string
}