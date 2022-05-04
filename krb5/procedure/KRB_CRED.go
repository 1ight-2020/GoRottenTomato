package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
	"reflect"
	"time"
)

type KRB_CRED struct {
	Pvno       int
	Msg_Type   int
	Tickets    []ticket.Ticket
	Enc_Part   types.EncryptedData
	DecEncPart EncKrbCredPart
}

type EncKrbCredPart struct {
	Ticket_Info []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce       int               `asn1:"optional,explicit,tag:1"`
	Timestamp   time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec        int               `asn1:"optional,explicit,tag:3"`
	S_Address   types.HostAddress `asn1:"optional,explicit,tag:4"`
	R_Address   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

type KrbCredInfo struct {
	Key        types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm     string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName      types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags      asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime   time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime  time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime    time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	Renew_Till time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm     string              `asn1:"generalstring,optional,explicit,tag:8"`
	SName      types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr      types.HostAddresses `asn1:"optional,explicit,tag:10"`
}


type mKRB_CRED struct {
	Pvno     int                    `asn1:"explicit,tag:0"`
	Msg_Type int                    `asn1:"explicit,tag:1"`
	Tickets  ticket.SeqOfRawTickets `asn1:"explicit,tag:2"`
	Enc_Part types.EncryptedData    `asn1:"explicit,tag:3"`
}

type umKRB_CRED struct {
	Pvno     int                    `asn1:"explicit,tag:0"`
	Msg_Type int                    `asn1:"explicit,tag:1"`
	Tickets  asn1.RawValue          `asn1:"explicit,tag:2"`
	Enc_Part types.EncryptedData    `asn1:"explicit,tag:3"`
}

func (org *EncKrbCredPart)Marshal() ([]byte, error) {
	return asn1.MarshalWithParams(*org, fmt.Sprintf("application,explicit,tag:%d", flags.EncKrbCredPart))
}

func (org *EncKrbCredPart)Unmarshal(data []byte) error {
	_, err := asn1.UnmarshalWithParams(data, org, fmt.Sprintf("application,explicit,tag:%v", flags.EncKrbCredPart))
	if err != nil {
		return fmt.Errorf("error in EncKrbCredPart unmarshaling %v", err)
	}
	return nil
}

func (org *KRB_CRED)DecryptEncpart(key types.EncryptionKey) error {
	encData, err := crypto.DecryptEncPart(org.Enc_Part, key, flags.KRB_CRED_ENCPART)
	if err != nil {
		return err
	}
	var dekcp EncKrbCredPart
	err = dekcp.Unmarshal(encData)
	if err != nil {
		return err
	}
	org.DecEncPart = dekcp
	return nil
}

func (org *KRB_CRED)Marshal() ([]byte, error) {
	m := mKRB_CRED{
		Pvno: org.Pvno,
		Msg_Type: org.Msg_Type,
	}

	err := m.Tickets.AddTickets(org.Tickets)
	if err != nil {
		return nil, err
	}

	mdp, err := org.DecEncPart.Marshal()
	if err != nil {
		return nil, err
	}

	m.Enc_Part.EType = org.Enc_Part.EType
	m.Enc_Part.Cipher = mdp

	return asn1.MarshalWithParams(m, fmt.Sprintf("application,explicit,tag:%d", flags.KRB_CRED))
}

func (org *KRB_CRED)Unmarshal(data []byte) error {
	var m umKRB_CRED
	_, err := asn1.UnmarshalWithParams(data, &m, fmt.Sprintf("application,explicit,tag:%v", flags.KRBCred))
	if err != nil {
		return fmt.Errorf("unmarshal KRB_CRED failed %v", err)
	}
	if m.Msg_Type != flags.KRB_CRED {
		return fmt.Errorf("unmarshal KRB_CRED Msg_Type error")
	}

	var tickets []ticket.Ticket

	tickets, err = ticket.UnmarshalTicketsSequence(m.Tickets)
	if err != nil {
		return err
	}


	decPart := m.Enc_Part.Cipher
	err = org.DecEncPart.Unmarshal(decPart)
	if err != nil {
		return fmt.Errorf("decEncPart unmarshal failed %v", err)
	}

	org.Pvno     = m.Pvno
	org.Msg_Type = m.Msg_Type
	org.Enc_Part = m.Enc_Part
	org.Tickets  = tickets

	return nil
}

func (org KRB_CRED)IsEmpty() bool {
	return reflect.DeepEqual(org, KRB_CRED{})
}