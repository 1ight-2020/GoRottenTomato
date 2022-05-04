package module

import (
	"GoRottenTomato/krb5/procedure"
	"fmt"
)

func Describe(data string) error {
	decode, err := getTGT(data)
	if err != nil {
		return fmt.Errorf("describe failed %v", err)
	}
	cred := &procedure.KRB_CRED{}
	err = cred.Unmarshal(decode)
	if err != nil {
		return fmt.Errorf("describe failed %v", err)
	}
	Display(cred)
	//fmt.Printf("$krb5asrep$%d$%s@%s:%x$%x", asrep.KDC_REP.Enc_Part.EType, asrep.CName.Name_String[0], asrep.KDC_REP.CRealm, asrep.KDC_REP.Enc_Part.Cipher[0:16], asrep.KDC_REP.Enc_Part.Cipher[16:])
	return nil
}

