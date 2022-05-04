package types

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/flags"
	"fmt"
	"time"
)

type PA_DATA struct {
	Padata_Type  int32  `asn1:"explicit,tag:1"`
	Padata_Value []byte `asn1:"explicit,tag:2"`
}

type PA_ENC_TS_ENC struct {
	Patimestamp time.Time `asn1:"generalized,explicit,tag:0"`
	Pausec      int       `asn1:"optional,explicit,tag:1"`
}

//https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.2
type PADataSequence []PA_DATA

//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/765795ba-9e05-4220-9bd3-b34464e413a7
type KERB_PA_PAC_REQUEST struct {
	Include bool `asn1:"explicit,tag:0"`
}

func NewPAData(paDataType int32, val interface{}) (*PA_DATA, error) {
	paDatavalue, err := asn1.Marshal(val)
	if err != nil {
		return nil, fmt.Errorf("newPAData Failed %v", err)
	}
	paData := &PA_DATA{
		Padata_Type: paDataType,
		Padata_Value: paDatavalue,
	}
	return paData, nil
}

//KERB-PA-PAC-REQUEST ::= SEQUENCE {
//include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
//--If FALSE, and PAC present, remove PAC
//}
func NewKerbPaPacREQUEST(nopac bool) (*PA_DATA, error) {
	return NewPAData(flags.PA_PAC_REQUEST, KERB_PA_PAC_REQUEST{!nopac,
	})
}

func (pas *PADataSequence)Unmarshal(data []byte) error {
	_, err := asn1.Unmarshal(data, pas)
	return err
}

type ETYPE_INFO_ENTRY struct {
	Etype int32  `asn1:"explicit,tag:0"`
	Salt  []byte `asn1:"explicit,optional,tag:1"`
}

type ETypeINFO []ETYPE_INFO_ENTRY

func (org *ETypeINFO)Unmarshal(data []byte) error {
	_, err := asn1.Unmarshal(data, org)
	return err
}

type ETYPE_INFO2_ENTRY struct {
	Etype     int32  `asn1:"explicit,tag:0"`
	Salt      []byte `asn1:"explicit,optional,tag:1"`
	S2kparams []byte `asn1:"explicit,optional,tag:2"`
}

type ETypeINFO2 []ETYPE_INFO2_ENTRY

func (org *ETypeINFO2)Unmarshal(data []byte) error {
	_, err := asn1.Unmarshal(data, org)
	return err
}

func (org *PA_DATA)GetETypeINFO() (d ETypeINFO2, err error)  {
	if org.Padata_Type != flags.PA_ETYPE_INFO {
		err = fmt.Errorf("EType ID Expected:%v Actually:%v", flags.PA_ETYPE_INFO, org.Padata_Type)
	}
	_, err = asn1.Unmarshal(org.Padata_Value, &d)
	return
}

func (org *PA_DATA)GetETypeINFO2() (d ETypeINFO2, err error)  {
	if org.Padata_Type != flags.PA_ETYPE_INFO2 {
		err = fmt.Errorf("EType ID Expected:%v Actually:%v", flags.PA_ETYPE_INFO2, org.Padata_Type)
	}
	_, err = asn1.Unmarshal(org.Padata_Value, &d)
	return
}
