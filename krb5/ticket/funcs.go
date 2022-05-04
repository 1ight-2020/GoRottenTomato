package ticket

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/flags"
	"fmt"
)


func MarshalTicket(tkts []Ticket) (asn1.RawValue, error) {
	raw := asn1.RawValue{
		Class: 2,
		IsCompound: true,
	}

	if len(tkts) < 1 {
		return raw, nil
	}

	var btkts []byte
	for _, value := range tkts{
		data, err := value.Marshal()
		if err != nil {
			return raw, err
		}
		btkts = append(btkts, data...)
	}
	btkts = append(funcs.MarshalLengthBytes(len(btkts)), btkts...)
	btkts = append([]byte{byte(32 + asn1.TagSequence)}, btkts...)

	raw.Bytes = btkts
	return raw, nil
}

func UnmarshalTicket(data []byte) (ticket Ticket, err error) {
	err = ticket.Unmarshal(data)
	return
}

func UnmarshalTicketsSequence(in asn1.RawValue) ([]Ticket, error) {
	b := in.Bytes
	p := 1 + GetNumberBytesInLengthHeader(in.Bytes)
	var tkts []Ticket
	var raw asn1.RawValue
	for p < (len(b)) {
		_, err := asn1.UnmarshalWithParams(b[p:], &raw, fmt.Sprintf("application,tag:%d", flags.Ticket))
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed getting length of ticket: %v", err)
		}
		t, err := unmarshalTicket(b[p:])
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed: %v", err)
		}
		p += len(raw.FullBytes)
		tkts = append(tkts, t)
	}
	MarshalTicketSequence(tkts)
	return tkts, nil
}

func unmarshalTicket(b []byte) (t Ticket, err error) {
	err = t.Unmarshal(b)
	return
}

func GetNumberBytesInLengthHeader(b []byte) int {
	if int(b[1]) <= 127 {
		return 1
	}
	return 1 + int(b[1]) - 128
}

func MarshalTicketSequence(tkts []Ticket) (asn1.RawValue, error) {
	raw := asn1.RawValue{
		Class:      2,
		IsCompound: true,
	}
	if len(tkts) < 1 {
		return raw, nil
	}
	var btkts []byte
	for i, t := range tkts {
		b, err := t.Marshal()
		if err != nil {
			return raw, fmt.Errorf("error marshaling ticket number %d in sequence of tickets", i+1)
		}
		btkts = append(btkts, b...)
	}

	btkts = append(funcs.MarshalLengthBytes(len(btkts)), btkts...)
	btkts = append([]byte{byte(32 + asn1.TagSequence)}, btkts...)
	raw.Bytes = btkts
	return raw, nil
}

var ticketFlagsMap = map[int]string{
	flags.Reserved               :  "reserved",
	flags.Forwardable            :  "forwardable",
	flags.Forwarded              :  "forwarded",
	flags.Proxiable              :  "proxiable",
	flags.Proxy                  :  "proxy",
	flags.Allow_Postdate         :  "allow-postdate",
	flags.Postdated              :  "postdated",
	flags.Invalid                :  "invalid",
	flags.Renewable              :  "renewable",
	flags.Initial                :  "initial",
	flags.PreAuthent             :  "pre-authent",
	flags.HwAuthent              :  "hwauthent",
	flags.TransitedPolicyChecked :  "transited-policy-checked",
	flags.OkAsDelegate           :  "ok-as-delegate",
	flags.CONSTRAINED_DELEGATION :  "DELEGATION",
	flags.NameCanonicalize       :  "name-canonicalize",
}

func DisplayTickets(ticketsFlags asn1.BitString) []string {
	flag := make([]string, 0)
	for i := flags.Reserved; i <= flags.NameCanonicalize; i++ {
		if ticketsFlags.At(i) == 1 {
			flag = append(flag, ticketFlagsMap[i])
		}
	}
	return flag
}