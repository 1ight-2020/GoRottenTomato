package rfc4757

import "encoding/binary"

func UsageToMSMsgType(usage uint32) []byte {
	switch usage {
	case 3:
		usage = 8
	case 9:
		usage = 8
	case 23:
		usage = 13
	}
	tb := make([]byte, 4)
	binary.PutUvarint(tb, uint64(usage))
	return tb
}
