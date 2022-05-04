package S4U2

import (
	"GoRottenTomato/krb5/AskTGS"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"encoding/base64"
	"fmt"
	"time"
)

func S4U2Proxy(tgt, tgs procedure.KRB_CRED, dcIP string, spn types.PrincipalName) (procedure.KRB_CRED, error) {
	fmt.Printf("[*]Starting S4U2Proxy\n")
	fmt.Printf("[*]Building PA-PAC-OPTIONS\n")
	var cred procedure.KRB_CRED
	papacoptions := types.NewPaPacOptions(3)
	data, err := papacoptions.Marshal()
	if err != nil {
		return cred, fmt.Errorf("S4U2Proxy Error %v", err)
	}
	papacdata := types.PA_DATA{
		Padata_Type:  flags.PA_PAC_OPTIONS,
		Padata_Value: data,
	}

	kflags := types.GetKerberosFlags(flags.Forwardable, flags.Renewable, flags.CONSTRAINED_DELEGATION, flags.Renewable_OK)
	ntgs := procedure.NewTGSREQ(kflags, tgt.Tickets[0].Realm, tgt.DecEncPart.Ticket_Info[0].PName, spn, tgt.DecEncPart.Ticket_Info[0].StartTime.Add(time.Hour * 24 * 7))
	ntgs.Req_Body.Additional_Tickets = tgs.Tickets
	ntgs.SetPAData(tgt.Tickets[0], tgt.DecEncPart.Ticket_Info[0].Key)
	ntgs.Padata = append(ntgs.Padata, papacdata)

	fmt.Printf("[*]Starting request S4U2Proxy\n")
	ntgsrep, err := AskTGS.AskTGS(*ntgs, dcIP, tgt.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return cred, err
	}
	if !ntgsrep.Check(flags.TGSREP) {
		return cred, fmt.Errorf("asn tag check failed")
	}
	fmt.Printf("[+]S4U2proxy Sucessful!\n")
	ncred := ntgsrep.GetCRED()
	blob, err := ncred.Marshal()
	if err != nil {
		return cred, err
	}
	fmt.Printf("[+]Got a TGS for %s@%s to %s/%s\n", ncred.DecEncPart.Ticket_Info[0].PName.Name_String[0], ncred.DecEncPart.Ticket_Info[0].PRealm, ncred.Tickets[0].SName.Name_String[0], ncred.Tickets[0].SName.Name_String[1])
	fmt.Printf("[*]Base64 S4U2Proxy TGS:\n\n%s\n\n", base64.StdEncoding.EncodeToString(blob))
	return *ncred, nil
}
