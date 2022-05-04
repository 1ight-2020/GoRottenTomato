package funcs

import (
	"GoRottenTomato/asn1"
	"crypto/rand"
	"math"
	"math/big"
)


func GetNonce() int {
	var count int
LOOP: nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if count > 7 {
		return 1760276845
	}
	if err != nil {
		count ++
		goto LOOP
	}
	value := int(nonce.Int64())
	if value == 12381973  || value == 1818848256{
		count ++
		goto LOOP
	}
	return value
}

func AddASNTag(data []byte, tag int) []byte {
	raw := asn1.RawValue{
		Class: asn1.ClassApplication,
		IsCompound: true,
		Tag: tag,
		Bytes: data,
	}
	ser, _ := asn1.Marshal(raw)
	return ser
}

func MarshalLengthBytes(l int) []byte {
	if l <= 127 {
		return []byte{byte(l)}
	}
	var b []byte
	p := 1
	for i := 1; i < 127; {
		b = append([]byte{byte((l % (p * 256)) / p)}, b...)
		p = p * 256
		l = l - l%p
		if l <= 0 {
			break
		}
	}
	return append([]byte{byte(128 + len(b))}, b...)
}