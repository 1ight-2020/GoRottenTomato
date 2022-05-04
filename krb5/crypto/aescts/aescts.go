package aescts

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func Encrypt(key, iv, plaintext []byte) ([]byte, []byte, error) {
	l := len(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("Error creating cipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	m := make([]byte, len(plaintext))
	copy(m, plaintext)

	if l <= aes.BlockSize {
		m, _ = zeroPad(m, aes.BlockSize)
		mode.CryptBlocks(m, m)
		return m, m, nil
	}
	if l%aes.BlockSize == 0 {
		mode.CryptBlocks(m, m)
		iv = m[len(m)-aes.BlockSize:]
		rb, _ := swapLastTwoBlocks(m, aes.BlockSize)
		return iv, rb, nil
	}
	m, _ = zeroPad(m, aes.BlockSize)
	rb, pb, lb, err := tailBlocks(m, aes.BlockSize)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("Error tailing blocks: %v", err)
	}
	var ct []byte
	if rb != nil {
		mode.CryptBlocks(rb, rb)
		iv = rb[len(rb)-aes.BlockSize:]
		mode = cipher.NewCBCEncrypter(block, iv)
		ct = append(ct, rb...)
	}
	mode.CryptBlocks(pb, pb)
	mode = cipher.NewCBCEncrypter(block, pb)
	mode.CryptBlocks(lb, lb)
	ct = append(ct, lb...)
	ct = append(ct, pb...)
	return lb, ct[:l], nil
}

func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	ct := make([]byte, len(ciphertext))
	copy(ct, ciphertext)
	if len(ct) < aes.BlockSize {
		return []byte{}, fmt.Errorf("Ciphertext is not large enough. It is less that one block size. Blocksize:%v; Ciphertext:%v", aes.BlockSize, len(ct))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating cipher: %v", err)
	}
	var mode cipher.BlockMode

	if len(ct)%aes.BlockSize == 0 {
		if len(ct) > aes.BlockSize {
			ct, _ = swapLastTwoBlocks(ct, aes.BlockSize)
		}
		mode = cipher.NewCBCDecrypter(block, iv)
		message := make([]byte, len(ct))
		mode.CryptBlocks(message, ct)
		return message[:len(ct)], nil
	}

	crb, cpb, clb, _ := tailBlocks(ct, aes.BlockSize)
	v := make([]byte, len(iv), len(iv))
	copy(v, iv)
	var message []byte
	if crb != nil {
		rb := make([]byte, len(crb))
		mode = cipher.NewCBCDecrypter(block, v)
		v = crb[len(crb)-aes.BlockSize:]
		mode.CryptBlocks(rb, crb)
		message = append(message, rb...)
	}

	pb := make([]byte, aes.BlockSize)
	mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pb, cpb)
	npb := aes.BlockSize - len(ct)%aes.BlockSize
	clb = append(clb, pb[len(pb)-npb:]...)

	lb := make([]byte, aes.BlockSize)
	mode = cipher.NewCBCDecrypter(block, v)
	v = clb
	mode.CryptBlocks(lb, clb)
	message = append(message, lb...)

	mode = cipher.NewCBCDecrypter(block, v)
	mode.CryptBlocks(cpb, cpb)
	message = append(message, cpb...)

	return message[:len(ct)], nil
}

func tailBlocks(b []byte, c int) ([]byte, []byte, []byte, error) {
	if len(b) <= c {
		return []byte{}, []byte{}, []byte{}, errors.New("bytes slice is not larger than one block so cannot tail")
	}
	var lbs int
	if l := len(b) % aes.BlockSize; l == 0 {
		lbs = aes.BlockSize
	} else {
		lbs = l
	}
	lb := b[len(b)-lbs:]
	pb := b[len(b)-lbs-c : len(b)-lbs]
	if len(b) > 2*c {
		rb := b[:len(b)-lbs-c]
		return rb, pb, lb, nil
	}
	return nil, pb, lb, nil
}

func swapLastTwoBlocks(b []byte, c int) ([]byte, error) {
	rb, pb, lb, err := tailBlocks(b, c)
	if err != nil {
		return nil, err
	}
	var out []byte
	if rb != nil {
		out = append(out, rb...)
	}
	out = append(out, lb...)
	out = append(out, pb...)
	return out, nil
}

func zeroPad(b []byte, m int) ([]byte, error) {
	if m <= 0 {
		return nil, errors.New("Invalid message block size when padding")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("Data not valid to pad: Zero size")
	}
	if l := len(b) % m; l != 0 {
		n := m - l
		z := make([]byte, n)
		b = append(b, z...)
	}
	return b, nil
}
