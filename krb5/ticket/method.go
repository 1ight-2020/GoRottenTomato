package ticket

import (
	"GoRottenTomato/asn1"
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/flags"
	"fmt"
)

func (ticket *Ticket)Marshal() ([]byte, error)  {
	data, err := asn1.Marshal(*ticket)
	if err !=nil {
		return nil, fmt.Errorf("ticket marshal error %v", err)
	}
	data = funcs.AddASNTag(data, flags.Ticket)
	return data, nil
}

func (ticket *Ticket)Unmarshal(data []byte) (err error) {
	_, err = asn1.UnmarshalWithParams(data, ticket, fmt.Sprintf("application,explicit,tag:%d", flags.Ticket))
	return
}

func (org *Ticket)RawValue() (*asn1.RawValue, error) {
	data, err := asn1.Marshal(*(org))
	if err != nil {
		return nil, err
	}
	rv := &asn1.RawValue{
		Class: asn1.ClassApplication,
		IsCompound: true,
		Tag: flags.Ticket,
		Bytes: data,
	}
	return rv, nil
}

func (org *SeqOfRawTickets)AddTickets(tickets []Ticket) error {
	for _, ticket := range tickets {
		r, err := ticket.RawValue()
		if err != nil {
			return err
		}

		(*org) = append(*org, *r)
	}
	return nil
}
