package procedure

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/KRBError"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"fmt"
)

type AS_REP struct {
	KDC_REP
}

func (org *AS_REP)Unmarshal(data []byte) error {
	var m mKDC_REP
	_, err := asn1.UnmarshalWithParams(data, &m, fmt.Sprintf("application,explicit,tag:%v", flags.ASREP))
	if err != nil {
		return KRBError.ProcessUnmarshalReplyError(data, err)
	}
	if m.Msg_Type != flags.KRB_AS_REP {
		return fmt.Errorf("message ID does not indicate an AS_REP")
	}
	t, err := ticket.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return fmt.Errorf("ticket unmarshaling failed in AS_REP")
	}
	org.KDC_REP = KDC_REP{
		Pvno: m.Pvno,
		Msg_Type: m.Msg_Type,
		Padata: m.Padata,
		CRealm: m.CRealm,
		CName: m.CName,
		Ticket: t,
		Enc_Part: m.Enc_Part,
	}
	return nil
}

func (org *AS_REP)DecryptEncPart(key types.EncryptionKey) (err error) {
	plaintext, err := crypto.DecryptEncPart(org.KDC_REP.Enc_Part, key, flags.AS_REP_ENCPART)
	if err != nil {
		return
	}
	var ekrp EncKDCRepPart
	ekrp.Key.KeyType = 23
	err = ekrp.Unmarshal(plaintext)
	if err != nil {
		return fmt.Errorf("unmarshaling AS_REP EncKDCRepPart error %v", err)
	}
	org.DecryptedEncPart = ekrp
	return
}


func (org *AS_REP)GetTGT() *KRB_CRED {
	info := org.KDC_REP.DecryptedEncPart.GetKrbCredInfo()
	info.PRealm = org.CRealm
	info.PName = org.CName
	cred := &KRB_CRED{
		Pvno: flags.PVNO,
		Msg_Type: flags.KRB_CRED,
		Tickets: []ticket.Ticket{org.KDC_REP.Ticket},
		DecEncPart: EncKrbCredPart{
			Ticket_Info: []KrbCredInfo{info},
		},
	}
	return cred
}