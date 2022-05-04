package types

type AuthorizationDataEntry struct {
	AD_Type int32  `asn1:"explicit,tag:0"`
	AD_Data []byte `asn1:"explicit,tag:1"`
}

type AuthorizationData []AuthorizationDataEntry

