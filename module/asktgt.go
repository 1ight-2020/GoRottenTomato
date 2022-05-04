package module

import (
	"GoRottenTomato/krb5/AskTGT"
	"encoding/base64"
	"fmt"
)

func ASKTGT(domain, username, password, dcIP, hash, path string, noPac bool, eType int32) error {
	asrep, err := AskTGT.AskTGT(domain, username, password, dcIP, hash, noPac, eType)
	if err != nil {
		return fmt.Errorf("[-]asktgt error: %v\n", err)
	}
	cred := asrep.GetTGT()
	data, err := cred.Marshal()
	if err != nil {
		return fmt.Errorf("[-]asktgt error: %v", err)
	}
	fmt.Printf("[+]AskTGT Sucessful!\n")

	err = saveFile(path, data)
	if err != nil {
		return err
	}
	fmt.Printf("[*]Base64(%s):\n\n%s\n", path, base64.StdEncoding.EncodeToString(data))
	return nil
}
