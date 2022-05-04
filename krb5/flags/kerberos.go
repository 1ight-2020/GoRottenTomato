package flags

const (
	PVNO = 5 //Kerberos Version
)

//PreAuthentication Data Types
//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2
const (
	PA_PW_SALT     int32 = 3
	PA_ETYPE_INFO  int32 = 11
	PA_ETYPE_INFO2 int32 = 19
	PA_PAC_REQUEST int32 = 128
	PA_PAC_OPTIONS int32 = 167
)

//KDC Port
//https://datatracker.ietf.org/doc/html/rfc1510#section-8.2.1
const (
	KDC_PORT = 88
)

//Application Tag Numbers
//https://datatracker.ietf.org/doc/html/rfc4120#section-5.10
const (
	Ticket = 1
	AS_REQ = 10
)

//Message Types
//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.7
const (
	KRB_AS_REQ     = 10
	KRB_AS_REP     = 11
	KRB_TGS_REQ    = 12
	KRB_TGS_REP    = 13
	KRB_AP_REQ     = 14
	KRB_CRED       = 22
	EncKrbCredPart = 29
	KRB_ERROR      = 30 //Error response
)


//Error Codes
//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
const (
	KDC_ERR_PREAUTH_REQUIRED int32 = 25
)



//Kerberos Encryption Types
//https://ldapwiki.com/wiki/Kerberos%20Encryption%20Types
const (
	AES_128_CTS_HMAC_SHA1 = int32(17)
	AES_256_CTS_HMAC_SHA1 = int32(18)
	RC4_HMAC_MD5          = int32(23)
)

//Key Usage Values
//https://datatracker.ietf.org/doc/html/draft-ietf-cat-kerb-key-derivation
const (
	AS_REQ_PA_ENC_TIMESTAMP = 1
)

//padata-type
//https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7
const (
	PA_ENC_TIMESTAMP int32 = 2
)

//checksum types
const (
	HMAC_SHA1_96_AES128    int32 = 15
	HMAC_SHA1_96_AES256    int32 = 16
	KERB_CHECKSUM_HMAC_MD5 int32 = -138
)

//ASN1 application tag numbers
const (
	Authenticator = 2
	ASREQ         = 10
	ASREP         = 11
	TGSREQ        = 12
	TGSREP        = 13
	APREQ         = 14
	KRBCred       = 22
	EncASRepPart  = 25
	EncTGSRepPart = 26
	KRBError      = 30
)

//KerberosFlags
//https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1
//https://www.rfc-editor.org/rfc/rfc4120.txt
const (
	Reserved               = 0
	Forwardable            = 1
	Forwarded              = 2
	Proxiable              = 3
	Proxy                  = 4
	Allow_Postdate         = 5
	Postdated              = 6
	Invalid                = 7
	Renewable              = 8
	Initial                = 9
	PreAuthent             = 10
	HwAuthent              = 11
	TransitedPolicyChecked = 12
	OkAsDelegate           = 13
	CONSTRAINED_DELEGATION = 14
	NameCanonicalize       = 15
	Renewable_OK           = 27
	Enc_TKT_In_Skey        = 28
	Renew                  = 30
)

//Key usage numbers
//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.1
const (
	AS_REP_ENCPART                          = 3
	TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR = 7
	TGS_REP_ENCPART_SESSION_KEY             = 8
	AP_REQ_AUTHENTICATOR                    = 11
	KRB_CRED_ENCPART                        = 14
)

//pre-authentication types
//https://datatracker.ietf.org/doc/html/rfc1510
const (
	PA_TGS_REQ  int32 = 1
	PA_FOR_USER int32 = 129
)

