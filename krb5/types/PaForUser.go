package types

import (
	"GoRottenTomato/asn1"
	"bytes"
	"encoding/binary"
	"strings"
)

//From https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a

/*
   PA-FOR-USER ::= SEQUENCE {
      -- PA TYPE 129
      userName              [0] PrincipalName,
      userRealm             [1] Realm,
      cksum                 [2] Checksum,
      auth-package          [3] KerberosString
   }
*/

type PA_FOR_USER struct {
	UserName     PrincipalName `asn1:"explicit,tag:0"`
	UserRealm    string        `asn1:"generalstring,explicit,tag:1"`
	Cksum        Checksum      `asn1:"explicit,optional,tag:2"`
	Auth_Package string        `asn1:"generalstring,explicit,tag:3"`
}

func NewPAFORUSER(username PrincipalName, realm string) PA_FOR_USER {
	return PA_FOR_USER{
		UserName:     username,
		UserRealm:    strings.ToUpper(realm),
		Cksum:        Checksum{},
		Auth_Package: "Kerberos",
	}
}

func (org *PA_FOR_USER)Marshal() ([]byte, error) {
	eb, err := asn1.Marshal(*org)
	if err != nil {
		return eb, err
	}
	return eb, nil
}

func (org PA_FOR_USER)GetS4UByteArray() []byte {
	name := make([]byte, 4)
	binary.LittleEndian.PutUint32(name, uint32(org.UserName.Name_Type))
	var buffer bytes.Buffer
	buffer.Write(name)
	buffer.Write([]byte(org.UserName.Name_String[0]))
	buffer.Write([]byte(org.UserRealm))
	buffer.Write([]byte(org.Auth_Package))
	return buffer.Bytes()
}