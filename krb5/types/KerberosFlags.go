package types

import "GoRottenTomato/asn1"

func NewKrbFlags() asn1.BitString {
	return NewKerberosFlagsFromUInt32(0)
}

func NewKerberosFlagsFromUInt32(f uint32) asn1.BitString {
	flags := asn1.BitString{}
	flags.Bytes = []byte{
		byte(f & 0xFF000000 >> 24),
		byte(f & 0x00FF0000 >> 16),
		byte(f & 0x0000FF00 >> 8),
		byte(f & 0x000000FF >> 0),
	}
	flags.BitLength = 4 * 8

	return flags
}

func SetKerberosFlag(kFlags *asn1.BitString, flag int) {
	i := flag / 8
	p := uint(7 - (flag - 8*i))
	kFlags.Bytes[i] = kFlags.Bytes[i] | (1 << p)
}

func GetKerberosFlags(flags ...int) (flag asn1.BitString) {
	flag = NewKrbFlags()
	for _, value := range flags{
		SetKerberosFlag(&flag, value)
	}
	return
}