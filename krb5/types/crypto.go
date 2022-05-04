package types

import (
	"GoRottenTomato/asn1"
)

type EncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	Kvno   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

func (org *EncryptedData)Marshal() ([]byte, error) {
	eb, err := asn1.Marshal(*org)
	if err != nil {
		return eb, err
	}
	return eb, nil
}

type Checksum struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}
