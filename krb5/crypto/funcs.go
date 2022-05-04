package crypto

import (
	"GoRottenTomato/krb5/crypto/etype"
	"GoRottenTomato/krb5/flags"
	"GoRottenTomato/krb5/types"
	"fmt"
	"unsafe"
)

func GetEType(id int32) (etype.EType) {
	switch id {
	case flags.AES_128_CTS_HMAC_SHA1:
		var eType AES128
		return eType
	case flags.AES_256_CTS_HMAC_SHA1:
		var eType AES256
		return eType
	case flags.RC4_HMAC_MD5:
		var eType RC4_HMAC
		return eType
	default:
		var eType RC4_HMAC
		return eType
	}
}
func GetETypeString(eTypeID int32) string {
	switch eTypeID {
	case flags.RC4_HMAC_MD5:
		return "RC4_HMAC_MD5"
	case flags.AES_128_CTS_HMAC_SHA1:
		return "AES_128_CTS_HMAC_SHA1"
	case flags.AES_256_CTS_HMAC_SHA1:
		return "AES_256_CTS_HMAC_SHA1"
	default:
		return ""
	}
}

func GetEncryptionKeyFromPassword(password, realm string, etype etype.EType, cname types.PrincipalName, pas types.PADataSequence) (types.EncryptionKey, error) {
	var key types.EncryptionKey
	sk2p := etype.GetDefaultStringToKeyParams()

	var salt string
	var paID int32

	for _, value := range pas{
		switch value.Padata_Type {
		case flags.PA_PW_SALT:
			if paID > value.Padata_Type {
				continue
			}
			//salt = string(value.Padata_Value)
			salt = *(*string)(unsafe.Pointer(&value.Padata_Value))

		case flags.PA_ETYPE_INFO:
			if paID > value.Padata_Type {
				continue
			}
			var eti types.ETypeINFO
			err := eti.Unmarshal(value.Padata_Value)
			if err != nil {
				return key, fmt.Errorf("unmashaling PA Data to PA-ETYPE-INFO failed %v", err)
			}
			//salt = string(eti[0].Salt)
			salt = *(*string)(unsafe.Pointer(&eti[0].Salt))

		case flags.PA_ETYPE_INFO2:
			if paID > value.Padata_Type {
				continue
			}
			var eti2 types.ETypeINFO2
			err := eti2.Unmarshal(value.Padata_Value)
			if err != nil {
				return key, fmt.Errorf("unmashaling PA Data to PA-ETYPE-INFO2 failed %v", err)
			}
			if len(eti2[0].S2kparams) == 4 {
				//sk2p = string(eti2[0].S2kparams)
				sk2p = *(*string)(unsafe.Pointer(&eti2[0].S2kparams))
			}
			//salt = string(eti2[0].Salt)
			salt = *(*string)(unsafe.Pointer(&eti2[0].Salt))
		}
	}

	if salt == "" {
		salt = cname.GetSalt(realm)
	}

	k, err := etype.StringToKey(password, salt, sk2p)
	if err != nil {
		return key, fmt.Errorf("deriving key from string failed %+v", err)
	}

	key = types.EncryptionKey{
		KeyType: etype.GetETypeID(),
		KeyValue: k,
	}
	return key, nil
}

func GetEncryptedData(data []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData
	eType := GetEType(key.KeyType)
	_, b, err := eType.EncryptMessage(key.KeyValue, data, usage)
	if err != nil {
		return ed, fmt.Errorf("get encrypted data failed %v", err)
	}
	ed = types.EncryptedData{
		EType: key.KeyType,
		//Kvno: kvno,
		Cipher: b,
	}
	return ed, nil
}

func DecryptEncPart(ciphertext types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	eType := GetEType(key.KeyType)
	plaintext, err := eType.DecryptMessage(key.KeyValue, ciphertext.Cipher, usage)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext failed %v", err)
	}
	return plaintext, err
}