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

type TGS_REP struct {
	KDC_REP
}

func (org *TGS_REP)Unmarshal(data []byte) error {
	var m mKDC_REP
	_, err := asn1.UnmarshalWithParams(data, &m, fmt.Sprintf("application,explicit,tag:%v", flags.TGSREP))
	if err != nil {
		return KRBError.ProcessUnmarshalReplyError(data, err)
	}
	tkt, err := ticket.UnmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return fmt.Errorf("error unmarshaling Ticket within TGS_REP %v", err)
	}
	org.KDC_REP = KDC_REP{
		Pvno:     m.Pvno,
		Msg_Type: m.Msg_Type,
		Padata:   m.Padata,
		CRealm:   m.CRealm,
		CName:    m.CName,
		Ticket:   tkt,
		Enc_Part: m.Enc_Part,
	}
	return nil
}

func (org *TGS_REP)DecryptEncPart(key types.EncryptionKey) error {
	data, err := crypto.DecryptEncPart(org.Enc_Part, key, flags.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return fmt.Errorf("decrypt tgsreq failed %v", err)
	}
	var enc EncKDCRepPart
	err = enc.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("decrypt tgsreq failed %v", err)
	}
	org.DecryptedEncPart = enc
	return nil
}

func (org *TGS_REP)GetCRED() *KRB_CRED {
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

func (org *TGS_REP)Check(tag int) bool {
	if tag == org.Msg_Type {
		return true
	}
	return false
}