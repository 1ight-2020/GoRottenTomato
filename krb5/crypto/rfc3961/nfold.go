package rfc3961

func Nfold(m []byte, n int) []byte {
	k := len(m) * 8

	//Get the lowest common multiple of the two bit sizes
	lcm := lcm(n, k)
	relicate := lcm / k
	var sumBytes []byte

	for i := 0; i < relicate; i++ {
		rotation := 13 * i
		sumBytes = append(sumBytes, rotateRight(m, rotation)...)
	}

	nfold := make([]byte, n/8)
	sum := make([]byte, n/8)
	for i := 0; i < lcm/n; i++ {
		for j := 0; j < n/8; j++ {
			sum[j] = sumBytes[j+(i*len(sum))]
		}
		nfold = onesComplementAddition(nfold, sum)
	}
	return nfold
}

func onesComplementAddition(n1, n2 []byte) []byte {
	numBits := len(n1) * 8
	out := make([]byte, numBits/8)
	carry := 0
	for i := numBits - 1; i > -1; i-- {
		n1b := getBit(&n1, i)
		n2b := getBit(&n2, i)
		s := n1b + n2b + carry

		if s == 0 || s == 1 {
			setBit(&out, i, s)
			carry = 0
		} else if s == 2 {
			carry = 1
		} else if s == 3 {
			setBit(&out, i, 1)
			carry = 1
		}
	}
	if carry == 1 {
		carryArray := make([]byte, len(n1))
		carryArray[len(carryArray)-1] = 1
		out = onesComplementAddition(out, carryArray)
	}
	return out
}

func rotateRight(b []byte, step int) []byte {
	out := make([]byte, len(b))
	bitLen := len(b) * 8
	for i := 0; i < bitLen; i++ {
		v := getBit(&b, i)
		setBit(&out, (i+step)%bitLen, v)
	}
	return out
}

func lcm(x, y int) int {
	return (x * y) / gcd(x, y)
}

func gcd(x, y int) int {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

func getBit(b *[]byte, p int) int {
	pByte := p / 8
	pBit := uint(p % 8)
	vByte := (*b)[pByte]
	vInt := int(vByte >> (8 - (pBit + 1)) & 0x0001)
	return vInt
}

func setBit(b *[]byte, p, v int) {
	pByte := p / 8
	pBit := uint(p % 8)
	oldByte := (*b)[pByte]
	var newByte byte
	newByte = byte(v<<(8-(pBit+1))) | oldByte
	(*b)[pByte] = newByte
}