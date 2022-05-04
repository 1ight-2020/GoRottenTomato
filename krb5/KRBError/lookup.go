package KRBError

import "fmt"

//Kerberos Error Codes
//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
const (
	KDC_ERR_C_PRINCIPAL_UNKNOWN int32 = 6
	KDC_ERR_S_PRINCIPAL_UNKNOWN int32 = 7
	KDC_ERR_NEVER_VALID         int32 = 11
	KDC_ERR_BADOPTION           int32 = 13
	KDC_ERR_ETYPE_NOTSUPP       int32 = 14
	KDC_ERR_PADATA_TYPE_NOSUPP  int32 = 16
	KDC_ERR_PREAUTH_FAILED      int32 = 24
	KDC_ERR_PREAUTH_REQUIRED    int32 = 25
	KRB_AP_ERR_BAD_INTEGRITY    int32 = 31
	KRB_AP_ERR_TKT_EXPIRED      int32 = 32
	KRB_AP_ERR_TKT_NYV          int32 = 33
	KRB_AP_ERR_BADMATCH         int32 = 36
	KRB_AP_ERR_SKEW             int32 = 37
	KRB_AP_ERR_MODIFIED         int32 = 41
	KRB_ERR_GENERIC             int32 = 60
	KDC_ERR_WRONG_REALM         int32 = 68
)

func Lookup(i int32) string {
	if s, ok := errorcodeLookup[i]; ok {
		return fmt.Sprintf("(0x%x) : %s", i, s)
	}
	return fmt.Sprintf("Unknown ErrorCode 0x%x", i)
}

var errorcodeLookup = map[int32]string{
	KDC_ERR_C_PRINCIPAL_UNKNOWN: "KDC_ERR_C_PRINCIPAL_UNKNOWN  Client not found in Kerberos database",
	KDC_ERR_S_PRINCIPAL_UNKNOWN: "KDC_ERR_S_PRINCIPAL_UNKNOWN  Server not found in Kerberos database",
	KDC_ERR_NEVER_VALID:         "KDC_ERR_NEVER_VALID  Requested start time is later than end time",
	KDC_ERR_BADOPTION:           "KDC_ERR_BADOPTION  KDC cannot accommodate requested option",
	KDC_ERR_ETYPE_NOTSUPP:       "KDC has no support for encryption type",
	KDC_ERR_PADATA_TYPE_NOSUPP:  "KDC_ERR_PADATA_TYPE_NOSUPP  KDC has no support for PADATA type",
	KDC_ERR_PREAUTH_FAILED:      "KDC_ERR_PREAUTH_FAILED  Pre-authentication information was invalid",
	KDC_ERR_PREAUTH_REQUIRED:    "KDC_ERR_PREAUTH_REQUIRED  Additional pre-authentication required",
	KRB_AP_ERR_BAD_INTEGRITY:    "KRB_AP_ERR_BAD_INTEGRITY  Integrity check on decrypted field failed",
	KRB_AP_ERR_TKT_EXPIRED:      "KRB_AP_ERR_TKT_EXPIRED  The ticket has expired",
	KRB_AP_ERR_TKT_NYV:          "KRB_AP_ERR_TKT_NYV  The ticket is not yet valid",
	KRB_AP_ERR_BADMATCH:         "KRB_AP_ERR_BADMATCH  The ticket and authenticator do not match",
	KRB_AP_ERR_SKEW:             "KRB_AP_ERR_SKEW  The clock skew is too great",
	KRB_AP_ERR_MODIFIED:         "KRB_AP_ERR_MODIFIED  Message stream modified and checksum didn't match",
	KRB_ERR_GENERIC:             "KRB_ERR_GENERIC  Generic error; the description is in the e-data field",
	KDC_ERR_WRONG_REALM:         "KDC_ERR_WRONG_REALM  KDC_ERR_WRONG_REALM Reserved for future use",
}