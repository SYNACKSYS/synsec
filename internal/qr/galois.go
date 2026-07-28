package qr

// Reed-Solomon over GF(256), the field the QR specification uses: arithmetic
// modulo the polynomial x^8 + x^4 + x^3 + x^2 + 1, which is 0x11D.
//
// Multiplication goes through logarithm tables rather than shifting bits each
// time. The tables are built once at start-up and are 512 bytes.

var (
	expTable [512]byte
	logTable [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		expTable[i] = byte(x)
		logTable[x] = byte(i)

		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	// Doubled, so a product of two logarithms can be looked up without
	// reducing the index first.
	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

// generatorPoly returns the polynomial whose roots are the first degree powers
// of the field generator.
func generatorPoly(degree int) []byte {
	poly := []byte{1}
	for i := 0; i < degree; i++ {
		next := make([]byte, len(poly)+1)
		for j, coeff := range poly {
			next[j] ^= coeff
			next[j+1] ^= gfMul(coeff, expTable[i])
		}
		poly = next
	}
	return poly
}

// reedSolomon returns the error correction codewords for one block.
func reedSolomon(data []byte, count int) []byte {
	generator := generatorPoly(count)

	// Long division of the message, shifted up by count, by the generator.
	remainder := make([]byte, len(data)+count)
	copy(remainder, data)

	for i := 0; i < len(data); i++ {
		lead := remainder[i]
		if lead == 0 {
			continue
		}
		for j, coeff := range generator {
			remainder[i+j] ^= gfMul(coeff, lead)
		}
	}
	return remainder[len(data):]
}
