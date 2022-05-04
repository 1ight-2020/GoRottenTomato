package rfc4757

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"io"
)

func Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	s := append([]byte(`signaturekey`), byte(0x00))
	mac := hmac.New(md5.New, key)
	mac.Write(s)
	Ksign := mac.Sum(nil)

	tb := UsageToMSMsgType(usage)
	p := append(tb, data...)
	h := md5.New()
	rb := bytes.NewReader(p)
	_, err := io.Copy(h, rb)
	if err != nil {
		return []byte{}, err
	}
	tmp := h.Sum(nil)

	mac = hmac.New(md5.New, Ksign)
	mac.Write(tmp)
	return mac.Sum(nil), nil
}

func HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
