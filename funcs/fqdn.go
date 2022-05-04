package funcs

import (
	"net"
	"strings"
)

type Domain struct {
	FQDN string
	IP   string
}

func GetDomain(relm, dcip string) (*Domain, error) {
	domain := new(Domain)

	domain.FQDN = relm
	domain.IP   = dcip

	if dcip != "" {
		ptr, _ := net.LookupAddr(dcip)
		if ptr[0] == "bogon" {
			return domain, nil
		}

		_, srv, err := net.LookupSRV("ldap", "tcp", relm)
		if err != nil {
			return domain, nil
		}
		ip, err := net.LookupHost(srv[0].Target)
		if err != nil {
			return domain, nil
		}
		domain.IP   = ip[0]
		domain.FQDN = srv[0].Target
		return domain, nil
	}

	ip, err := net.LookupHost(relm)
	if err != nil {
		return nil, err
	}
	ptr, err := net.LookupAddr(ip[0])
	if err != nil {
		return nil, err
	}
	domain.FQDN = relm
	domain.IP   = ip[0]
	if ptr[0] == "bogon" {
		return domain, nil
	}
	_, srv, err := net.LookupSRV("ldap", "tcp", relm)
	if err != nil {
		return domain, nil
	}
	for _, value := range srv{
		for _, addr := range ptr{
			if strings.Contains(value.Target, addr) {
				domain.FQDN = value.Target
				return domain, nil
			}
		}
	}
	domain.FQDN = relm
	return domain, nil
}

