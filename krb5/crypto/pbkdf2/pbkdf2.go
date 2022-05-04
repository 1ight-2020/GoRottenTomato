package pbkdf2

import (
	"crypto/hmac"
	"hash"
)

func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	return Key64(password, salt, int64(iter), int64(keyLen), h)
}

func Key64(password, salt []byte, iter, keyLen int64, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := int64(prf.Size())
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := int64(1); block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[int64(len(dk))-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := int64(2); n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}