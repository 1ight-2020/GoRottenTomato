package module

import (
	"GoRottenTomato/krb5/AskTGS"
	"GoRottenTomato/krb5/AskTGT"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

func asktgs(dcIP, path string, service string, cred procedure.KRB_CRED) error {
	fmt.Printf("[*]Building TGS-REQ request for %s \n", service)

	spn := types.NewPrincipalName(flags.NT_SRV_INST, service)
	kflags := types.GetKerberosFlags(flags.Renewable, flags.Renewable_OK)

	tgs := procedure.NewTGSREQ(kflags, cred.Tickets[0].Realm, cred.DecEncPart.Ticket_Info[0].PName, spn, cred.DecEncPart.Ticket_Info[0].StartTime.Add(time.Hour * 24 * 7))
	err := tgs.SetPAData(cred.Tickets[0], cred.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return err
	}

	tgsrep, err := AskTGS.AskTGS(*tgs, dcIP, cred.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return err
	}
	newcred := tgsrep.GetCRED()
	blob, err := newcred.Marshal()
	if err != nil {
		return err
	}
	fmt.Printf("[+]AskTGS Sucessful!\n")

	base := base64.StdEncoding.EncodeToString(blob)
	fmt.Printf("[*]Base64(%s):\n\n%s\n\n", path, base)
	Display(newcred)

	err = saveFile(path, blob)
	if err != nil {
		return err
	}
	return nil
}

func askTGSFromTGT(kirbi, dcIP string, service []string, save bool) error {
	cred, err := getUnmarshalTGT(kirbi)
	if err != nil {
		return err
	}

	printTGS(dcIP, service, *cred, save)
	return nil
}

func ASKTGS(domain, dcIP, username, password, hash, kirbi string, noPac, save bool, service []string, eType int32) error {
	if kirbi != "" {
		return askTGSFromTGT(kirbi, dcIP, service, save)
	}

	asrep, err := AskTGT.AskTGT(domain, username, password, dcIP, hash, noPac, eType)
	if err != nil {
		return fmt.Errorf("[-]asktgt error: %v\n", err)
	}
	fmt.Printf("[+]TGT request successful!\n")
	cred := asrep.GetTGT()
	printTGS(dcIP, service, *cred, save)
	return nil
}

func printTGS(dcIP string, service []string, cred procedure.KRB_CRED, save bool)  {
	var file string
	for _, spn := range service{
		if save {
			//TODO Support .kirbi && .ccache
			file = "TGS" + cred.DecEncPart.Ticket_Info[0].PName.Name_String[0] +"@" + cred.DecEncPart.Ticket_Info[0].PRealm + strings.Replace(spn, "/", "~", -1) + ".kirbi"
		}
		err := asktgs(dcIP, file, spn, cred)
		if err != nil {
			fmt.Printf("[-]%s request failed!\n%v\n\n", spn, err)
		}
	}
}