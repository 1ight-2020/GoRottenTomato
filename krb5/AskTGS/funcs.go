package AskTGS

import (
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"fmt"
)

func GetTGS(data []byte, key types.EncryptionKey) (*procedure.TGS_REP, error) {
	var tgsrep procedure.TGS_REP
	err := tgsrep.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	err = tgsrep.DecryptEncPart(key)
	if err != nil {
		return nil, fmt.Errorf("tgsrep decrypt enc part failed %v", err)
	}
	return &tgsrep, nil
}
