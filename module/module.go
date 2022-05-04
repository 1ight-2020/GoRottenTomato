package module

import (
	"GoRottenTomato/krb5/procedure"
	"flag"
	"fmt"
	"strings"
	"time"
)

func Parse(arg []string) {
	logo()
	if len(arg) < 1 {
		menu()
		return
	}
	switch arg[0] {
	case "asktgt":
		err := parseAskTGT(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	case "asktgs":
		err := parseAskTGS(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	case "describe":
		err := parseDescribe(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	case "renew":
		err := parseRenew(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	case "asreproast":
		err := parseAsRepRoast(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	case "s4u":
		err := parseS4U(arg[1:])
		if err != nil {
			fmt.Println(err)
		}
	default:
		menu()
	}
}

func parseAskTGT(arg []string) (err error) {
	set := flag.NewFlagSet("asktgt", flag.ContinueOnError)
	var domain   = set.String("domain", "", "Target domain name")
	var username = set.String("user", "", "Username")
	var password = set.String("password", "", "User's password")
	var dcIP     = set.String("dcIP", "", "Target KDC's IP address")
	var hash     = set.String("hash", "", "User's password hash")
	var eType    = set.String("etype", "rc4", "Kind of encryption key (rc4, aes128, aes256)")
	var path     = set.String("path", "", "File save path")
	var nopac    = set.Bool("nopac", false, "Whether to include pac, default false")

	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}

	*dcIP, err = getDomainIP(*domain, *dcIP, "AskTGT", "ask TGT")
	if err != nil {
		return err
	}
	etypeid := getEType(*eType)
	return ASKTGT(*domain, *username, *password, *dcIP, *hash, *path, *nopac, etypeid)
}

func parseAskTGS(arg []string) (err error) {
	set := flag.NewFlagSet("asktgs", flag.ContinueOnError)
	var domain      = set.String("domain", "", "Target domain name")
	var username    = set.String("user", "", "Username")
	var password    = set.String("password", "", "User's password")
	var dcIP        = set.String("dcIP", "", "Target KDC's IP address")
	var hash        = set.String("hash", "", "User's password hash")
	var eType       = set.String("etype", "rc4", "Kind of encryption key (rc4, aes128, aes256)")
	var kirbi       = set.String("tgt", "", "request TGS using the specified TGT (Base64TGT or .kirbi)")
	var servicename = set.String("service", "", "services must be specified, comma separated")
	var nopac       = set.Bool("nopac", false, "Whether to include pac, default false")
	var path        = set.Bool("path", false, "File save path, default false")
	
	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}

	*dcIP, err = getDomainIP(*domain, *dcIP, "AskTGS", "ask TGS")
	if err != nil {
		return err
	}
	service := strings.Split(*servicename, ",")
	etypeid := getEType(*eType)
	return ASKTGS(*domain, *dcIP, *username, *password, *hash, *kirbi, *nopac, *path, service, etypeid)
}

func parseDescribe(arg []string) (err error) {
	set := flag.NewFlagSet("describe", flag.ContinueOnError)
	var data = set.String("ticket", "", "Ticket that needs to be decrypted (Base64TGT or .kirbi)")
	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}
	return Describe(*data)
}

func parseRenew(arg []string) (err error) {
	set := flag.NewFlagSet("renew", flag.ContinueOnError)
	var kirbi = set.String("tgt", "", "Tickets that need to be renew (Base64TGT or .kirbi)")
	var dcIP  = set.String("dcIP", "", "Target KDC's IP address")
	var path  = set.String("path", "", "File save path")
	var till  = set.Duration("till", time.Hour * 24 * 7, "Ticket expiration date, default 7 days")
	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}
	return RENEW(*kirbi, *dcIP, *path, *till)
}

func parseAsRepRoast(arg []string) (err error) {
	set := flag.NewFlagSet("asreproast", flag.ContinueOnError)
	var domain   = set.String("domain", "", "Target domain name")
	var dcIP     = set.String("dcIP", "", "Target KDC's IP address")
	var username = set.String("user", "", "Username")
	var path     = set.String("path", "", "File save path")
	var format   = set.String("format", "john", "output format (john, hashcat)")
	var eType    = set.String("etype", "rc4", "Kind of encryption key (rc4, aes128, aes256)")

	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}

	*dcIP, err = getDomainIP(*domain, *dcIP, "AsrepRoast", "asreproast")
	if err != nil {
		return err
	}
	etypeid := getEType(*eType)
	return AS_REPRoast(*domain, *dcIP, *username, *path, *format, etypeid)
}

func parseS4U(arg []string) (err error) {
	set := flag.NewFlagSet("s4u", flag.ContinueOnError)
	var domain      = set.String("domain", "", "Target domain name")
	var username    = set.String("user", "", "Username")
	var password    = set.String("password", "", "User's password")
	var dcIP        = set.String("dcIP", "", "Target KDC's IP address")
	var hash        = set.String("hash", "", "User's password hash")
	var eType       = set.String("etype", "rc4", "Kind of encryption key (rc4, aes128, aes256)")
	var btgt        = set.String("tgt", "", "Base64 encoded TGT (Base64TGT or .kirbi)")
	var btgs        = set.String("tgs", "", "Base64 encoded TGS (Base64TGT or .kirbi)")
	var impersonate = set.String("impersonate", "", "Account to be impersonated")
	var service     = set.String("service", "", "target rbcd service")
	var alter       = set.String("alter", "", "Substitute in any service name")
	var nopac       = set.Bool("nopac", false, "Whether to include pac, default false")
	var save        = set.Bool("save", false, "Whether to save the TGS, default false")

	if len(arg) < 1 {
		set.PrintDefaults()
		return nil
	}
	err = set.Parse(arg)
	if err != nil {
		return nil
	}

	if *impersonate == "" {
		return fmt.Errorf("impersonate parameter must be specified")
	}

	*dcIP, err = getDomainIP(*domain, *dcIP, "AsrepRoast", "asreproast")
	if err != nil {
		return err
	}
	etypeid := getEType(*eType)

	var tgt *procedure.KRB_CRED
	if *btgt != "" {
		tgt, err = getUnmarshalTGT(*btgt)
		if err != nil {
			return fmt.Errorf("tgt unmarshaling error %v", err)
		}
	}else {
		tgt = &procedure.KRB_CRED{}
	}
	var tgs *procedure.KRB_CRED
	if *btgs != "" {
		tgs, err = getUnmarshalTGT(*btgs)
		if err != nil {
			return fmt.Errorf("tgs unmarshaling error %v", err)
		}
	}else {
		tgs = &procedure.KRB_CRED{}
	}
	var altservice []string
	if *alter == "" {
		altservice = nil
	}else {
		altservice = strings.Split(*alter, ",")
	}

	return S4U(*tgt, *tgs, *dcIP, *service, *impersonate, *domain, *username, *password, *hash, altservice, *nopac, *save, etypeid)
}
