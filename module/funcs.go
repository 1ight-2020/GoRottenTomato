package module

import (
	"GoRottenTomato/funcs"
	"GoRottenTomato/krb5/crypto"
	"GoRottenTomato/krb5/procedure"
	"GoRottenTomato/krb5/ticket"
	"GoRottenTomato/krb5/types"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func printFQDN(dc *funcs.Domain, action string) error {
	if dc.FQDN == "" {
		return fmt.Errorf("need specify the domain parameter")
	}else if dc.IP == "" {
		return fmt.Errorf("need specify the dcIP parameter")
	} else {
		fmt.Printf("[*]Target KDC name: %s\n", dc.FQDN)
		fmt.Printf("[*]Target KDC addr: %s\n", dc.IP)
		fmt.Printf("[*]Starting %s \n", action)
		return nil
	}
}

func getDomainIP(domain, dcIP, name, action string) (ip string, err error) {
	dc, err := funcs.GetDomain(domain, dcIP)
	if err != nil {
		return "", fmt.Errorf("[-]%s failed can not find %s %v", name, domain, err)
	}
	err = printFQDN(dc, action)
	if err != nil {
		return "", fmt.Errorf("[-]%s failed %v", action, err)
	}
	return dc.IP, nil
}

func Display(cred *procedure.KRB_CRED)  {
	var sname string
	if len(cred.DecEncPart.Ticket_Info[0].SName.Name_String) < 2 {
		sname = cred.DecEncPart.Ticket_Info[0].SName.Name_String[0]
	}else {
		sname = cred.DecEncPart.Ticket_Info[0].SName.Name_String[0] + "/" + cred.DecEncPart.Ticket_Info[0].SName.Name_String[1]
	}
	fmt.Printf("UserName       :  %s\n", cred.DecEncPart.Ticket_Info[0].PName.Name_String[0])
	fmt.Printf("UserRealm      :  %s\n", cred.DecEncPart.Ticket_Info[0].PRealm)
	fmt.Printf("ServiceName    :  %s\n", sname)
	fmt.Printf("ServiceRealm   :  %s\n", cred.DecEncPart.Ticket_Info[0].SRealm)
	fmt.Printf("StartTime      :  %v\n", cred.DecEncPart.Ticket_Info[0].StartTime)
	fmt.Printf("EndTime        :  %v\n", cred.DecEncPart.Ticket_Info[0].EndTime)
	fmt.Printf("RenewTill      :  %v\n", cred.DecEncPart.Ticket_Info[0].Renew_Till)
	fmt.Printf("Flags          :  %s\n", getFlags(cred))
	fmt.Printf("KeyType        :  %s\n", crypto.GetETypeString(cred.DecEncPart.Ticket_Info[0].Key.KeyType))
	fmt.Printf("EncPartKeyType :  %s\n", crypto.GetETypeString(cred.Tickets[0].Enc_Part.EType))
	fmt.Printf("Base64(key)    :  %s\n", getBase64Key(cred.DecEncPart.Ticket_Info[0].Key))
	fmt.Printf("\n\n")
}

func getFlags(cred *procedure.KRB_CRED) string {
	flag := ticket.DisplayTickets(cred.DecEncPart.Ticket_Info[0].Flags)
	if len(flag) < 1 {
		return "unknown flag"
	}
	var str string
	for key, value := range flag{
		if key == 0 {
			str = value
		}else {
			str = str + ", " + value
		}
	}
	return str
}

func getBase64Key(key types.EncryptionKey) string {
	return base64.StdEncoding.EncodeToString(key.KeyValue)
}

func getBase64EncPart(data types.EncryptedData) string {
	return base64.StdEncoding.EncodeToString(data.Cipher)
}

func getTGT(str string) ([]byte, error) {
	if str[(len(str)-6):] == ".kirbi" {
		f, err := os.Open(str)
		if err != nil {
			return nil, err
		}
		chunks := make([]byte, 0)
		buf := make([]byte, 1024)
		for {
			n, err := f.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			chunks = append(chunks, buf[:n]...)
		}
		return chunks, nil
	}

	decode, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return decode, nil
}

func saveFile(path string, data []byte) error {
	if path != "" {
		err := ioutil.WriteFile(path, data, 0644)
		if err != nil {
			return fmt.Errorf("[-]can not save %s: %v", path, err)
		}
		fmt.Printf("[+]Save %s Sucessful!\n\n", path)
	}
	return nil
}

func getUnmarshalTGT(data string) (*procedure.KRB_CRED, error) {
	decode, err := getTGT(data)
	if err != nil {
		return nil, fmt.Errorf("describe failed %v", err)
	}
	cred := &procedure.KRB_CRED{}
	err = cred.Unmarshal(decode)
	if err != nil {
		return nil, fmt.Errorf("describe failed %v", err)
	}
	return cred, nil
}

func getEType(eType string) int32 {
	switch eType {
	case "aes128":
		return 17
	case "aes256":
		return 18
	case "rc4":
		return 23
	default:
		return 23
	}
}

func logo()  {
	fmt.Println()
	fmt.Println(" _____                      _        ")
	fmt.Println("/__   \\___  _ __ ___   __ _| |_ ___  ")
	fmt.Println("  / /\\/ _ \\| '_ ` _ \\ / _` | __/ _ \\ ")
	fmt.Println(" / / | (_) | | | | | | (_| | || (_) |")
	fmt.Println(" \\/   \\___/|_| |_| |_|\\__,_|\\__\\___/ ")
	fmt.Println()
}

func menu()  {
	fmt.Println("  -asktgt\n      Request a TGT\n  -asktgs\n      Request a TGS\n  -describe\n      Describe the content of the ticket\n  -renew\n      Renew a ticket\n  -asreproast\n      asreproast attack\n  -s4u\n      ServiceForUser attack")
}