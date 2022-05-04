package types

import (
	"GoRottenTomato/asn1"
	"fmt"
)

/*
PA-PAC-OPTIONS ::= SEQUENCE {
        KerberosFlags
        -- Claims(0)
        -- Branch Aware(1)
        -- Forward to Full DC(2)
        -- Resource-based Constrained Delegation (3)
       }
*/

type PA_PAC_OPTIONS struct {
	KerberosFlags asn1.BitString `asn1:"explicit,tag:0"`
}

type PA_PAC_OPTIONS_SEQUENCE []PA_PAC_OPTIONS

func NewPaPacOptions(kflags ...int) *PA_PAC_OPTIONS {
	kflag := NewKrbFlags()
	for _, value := range kflags{
		SetKerberosFlag(&kflag, value)
	}
	pac := PA_PAC_OPTIONS{
		KerberosFlags: kflag,
	}
	return &pac
}

func (org *PA_PAC_OPTIONS)Marshal() ([]byte, error) {
	data, err := asn1.Marshal(*org)
	if err != nil {
		return nil, fmt.Errorf("PA-PAC-Options marshal failed")
	}
	return data, nil
}