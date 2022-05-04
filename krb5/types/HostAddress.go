package types

type HostAddress struct {
	Addr_Type int32  `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

type HostAddresses []HostAddress
