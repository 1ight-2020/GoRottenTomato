package crypto

import (
	"GoRottenTomato/krb5/crypto/common"
	"GoRottenTomato/krb5/crypto/rfc3961"
	"GoRottenTomato/krb5/crypto/rfc3962"
	"GoRottenTomato/krb5/flags"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

type AES256 struct {
}

func (e AES256)GetETypeID() int32 {
	return flags.AES_256_CTS_HMAC_SHA1
}

// GetHashID returns the checksum type ID number.
func (e AES256)GetHashID() int32 {
	return flags.HMAC_SHA1_96_AES256
}

// GetKeyByteSize returns the number of bytes for key of this etype.
func (e AES256)GetKeyByteSize() int {
	return 256 / 8
}

// GetKeySeedBitLength returns the number of bits for the seed for key generation.
func (e AES256)GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

// GetHashFunc returns the hash function for this etype.
func (e AES256)GetHashFunc() func() hash.Hash {
	return sha1.New
}

// GetMessageBlockByteSize returns the block size for the etype's messages.
func (e AES256)GetMessageBlockByteSize() int {
	return 1
}

// GetDefaultStringToKeyParams returns the default key derivation parameters in string form.
func (e AES256)GetDefaultStringToKeyParams() string {
	return "00001000"
}

// GetConfounderByteSize returns the byte count for confounder to be used during cryptographic operations.
func (e AES256)GetConfounderByteSize() int {
	return aes.BlockSize
}

// GetHMACBitLength returns the bit count size of the integrity hash.
func (e AES256)GetHMACBitLength() int {
	return 96
}

// GetCypherBlockBitLength returns the bit count size of the cypher block.
func (e AES256)GetCypherBlockBitLength() int {
	return aes.BlockSize * 8
}

// StringToKey returns a key derived from the string provided.
func (e AES256)StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	return rfc3962.StringToKey(secret, salt, s2kparams, e)
}

// RandomToKey returns a key from the bytes provided.
func (e AES256)RandomToKey(b []byte) []byte {
	return rfc3961.RandomToKey(b)
}

// EncryptData encrypts the data provided.
func (e AES256)EncryptData(key, data []byte) ([]byte, []byte, error) {
	return rfc3962.EncryptData(key, data, e)
}

// EncryptMessage encrypts the message provided and concatenates it with the integrity hash to create an encrypted message.
func (e AES256)EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	return rfc3962.EncryptMessage(key, message, usage, e)
}

// DecryptData decrypts the data provided.
func (e AES256)DecryptData(key, data []byte) ([]byte, error) {
	return rfc3962.DecryptData(key, data, e)
}

// DecryptMessage decrypts the message provided and verifies the integrity of the message.
func (e AES256)DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error) {
	return rfc3962.DecryptMessage(key, ciphertext, usage, e)
}

// DeriveKey derives a key from the protocol key based on the usage value.
func (e AES256)DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return rfc3961.DeriveKey(protocolKey, usage, e)
}

// DeriveRandom generates data needed for key generation.
func (e AES256)DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return rfc3961.DeriveRandom(protocolKey, usage, e)
}

// VerifyIntegrity checks the integrity of the plaintext message.
func (e AES256)VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return rfc3961.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}

// GetChecksumHash returns a keyed checksum hash of the bytes provided.
func (e AES256)GetChecksumHash(protocolKey, data []byte, usage uint32) ([]byte, error) {
	return common.GetHash(data, protocolKey, common.GetUsageKc(usage), e)
}

// VerifyChecksum compares the checksum of the message bytes is the same as the checksum provided.
func (e AES256)VerifyChecksum(protocolKey, data, chksum []byte, usage uint32) bool {
	c, err := e.GetChecksumHash(protocolKey, data, usage)
	if err != nil {
		return false
	}
	return hmac.Equal(chksum, c)
}