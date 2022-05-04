package rfc4757

import (
	"GoRottenTomato/krb5/crypto/etype"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/rand"
	"errors"
	"fmt"
)

func EncryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return []byte{}, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return []byte{}, fmt.Errorf("error creating RC4 cipher: %v", err)
	}
	ed := make([]byte, len(data))
	copy(ed, data)
	rc4Cipher.XORKeyStream(ed, ed)
	rc4Cipher.Reset()
	return ed, nil
}

func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	return EncryptData(key, data, e)
}

func EncryptMessage(key, data []byte, usage uint32, export bool, e etype.EType) ([]byte, error) {
	confounder := make([]byte, e.GetConfounderByteSize()) // size = 8
	_, err := rand.Read(confounder)
	if err != nil {
		return []byte{}, fmt.Errorf("error generating confounder: %v", err)
	}
	k1 := key
	k2 := HMAC(k1, UsageToMSMsgType(usage))
	toenc := append(confounder, data...)
	chksum := HMAC(k2, toenc)
	k3 := HMAC(k2, chksum)

	ed, err := EncryptData(k3, toenc, e)
	if err != nil {
		return []byte{}, fmt.Errorf("error encrypting data: %v", err)
	}

	msg := append(chksum, ed...)
	return msg, nil
}

func DecryptMessage(key, data []byte, usage uint32, export bool, e etype.EType) ([]byte, error) {
	checksum := data[:e.GetHMACBitLength()/8]
	ct := data[e.GetHMACBitLength()/8:]
	_, k2, k3 := deriveKeys(key, checksum, usage, export)

	pt, err := DecryptData(k3, ct, e)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting data: %v", err)
	}

	if !VerifyIntegrity(k2, pt, data, e) {
		return []byte{}, errors.New("integrity checksum incorrect")
	}
	return pt[e.GetConfounderByteSize():], nil
}

func VerifyIntegrity(key, pt, data []byte, e etype.EType) bool {
	chksum := HMAC(key, pt)
	return hmac.Equal(chksum, data[:e.GetHMACBitLength()/8])
}
