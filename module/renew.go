package module

import (
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/AskTGS"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"encoding/base64"
	"fmt"
	"time"
)

func RENEW(data, dcIP, path string, till time.Duration) error {
	cred, err := getUnmarshalTGT(data)
	if err != nil {
		return err
	}

	dc, err := funcs.GetDomain(cred.Tickets[0].Realm, dcIP)
	if err != nil {
		return fmt.Errorf("[-]renew failed can not find %s %v", cred.Tickets[0].Realm, err)
	}
	dcIP = dc.IP
	printFQDN(dc, "renew")

	fmt.Printf("[*]Building TGS-REQ renewal for: %s\\%s\n", cred.DecEncPart.Ticket_Info[0].PRealm , cred.DecEncPart.Ticket_Info[0].PName.Name_String[0] )

	kflags := types.GetKerberosFlags(flags.Renewable, flags.Renewable_OK, flags.Renew, flags.Forwardable)

	tgs := procedure.NewTGSREQ(kflags, cred.Tickets[0].Realm, cred.DecEncPart.Ticket_Info[0].PName, cred.DecEncPart.Ticket_Info[0].SName, cred.DecEncPart.Ticket_Info[0].StartTime.Add(till))
	tgs.SetPAData(cred.Tickets[0], cred.DecEncPart.Ticket_Info[0].Key)

	tgsrep, err := AskTGS.AskTGS(*tgs, dcIP, cred.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return err
	}

	newcred := tgsrep.GetCRED()
	tgt, err := newcred.Marshal()
	fmt.Printf("[+]TGT renewal request successful!\n")

	base := base64.StdEncoding.EncodeToString(tgt)
	err = saveFile(path, tgt)
	if err != nil {
		return err
	}
	fmt.Printf("[*]Base64:\n\n%s\n", base)
	return nil
}


