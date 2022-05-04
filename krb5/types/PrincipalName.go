package types

import (
	"strings"
	"unsafe"
)

type PrincipalName struct {
	Name_Type   int32    `asn1:"explicit,tag:0"`
	Name_String []string `asn1:"generalstring,explicit,tag:1"`
}

func (pn PrincipalName)GetSalt(realm string) string {
	var data []byte
	data = append(data, realm...)
	for _, n := range pn.Name_String {
		data = append(data, n...)
	}
	return *(*string)(unsafe.Pointer(&data))
}

func NewPrincipalName(ntype int32, spn string) PrincipalName {
	return PrincipalName{
		Name_Type: ntype,
		Name_String: strings.Split(spn, "/"),
	}
}