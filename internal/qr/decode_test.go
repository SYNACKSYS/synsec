package qr

import (
	"strings"
	"testing"
)

// Reading the symbol back.
//
// The other tests check the pieces. These check the thing a phone actually
// sees, because a symbol can be wrong in ways that are invisible to everyone
// who is not a scanner: it draws cleanly, it looks like a QR code, and no
// authenticator will read it. That is exactly what shipped, twice.
//
// Three of the checks below owe nothing to the encoder's own idea of what it
// is doing: the count of data modules against the figure the specification
// gives, the Reed-Solomon syndromes of every block, and the text that comes
// out at the end.

// remainderBits are the modules left over once the codewords are placed. They
// stay light and carry nothing.
var remainderBits = map[int]int{
	1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0,
}

// functionMap marks every module that is not data.
//
// Written out from the specification rather than taken from the encoder: when
// the encoder forgets to reserve something - as it did for the version block -
// the two disagree and the module count says so.
func functionMap(version int) [][]bool {
	size := 17 + 4*version
	m := make([][]bool, size)
	for i := range m {
		m[i] = make([]bool, size)
	}
	mark := func(x, y int) {
		if x >= 0 && y >= 0 && x < size && y < size {
			m[y][x] = true
		}
	}

	// The three finders, each with its separator: an eight by eight corner.
	for dy := 0; dy < 8; dy++ {
		for dx := 0; dx < 8; dx++ {
			mark(dx, dy)
			mark(size-1-dx, dy)
			mark(dx, size-1-dy)
		}
	}

	for i := 0; i < size; i++ {
		mark(i, 6)
		mark(6, i)
	}

	for _, x := range versions[version].alignment {
		for _, y := range versions[version].alignment {
			if (x == 6 && y == 6) || (x == 6 && y == size-7) || (x == size-7 && y == 6) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					mark(x+dx, y+dy)
				}
			}
		}
	}

	// The format area, both copies, and the module that is always dark.
	for i := 0; i <= 8; i++ {
		mark(8, i)
		mark(i, 8)
	}
	for i := 0; i < 8; i++ {
		mark(8, size-1-i)
		mark(size-1-i, 8)
	}

	if version >= 7 {
		for i := 0; i < 18; i++ {
			mark(size-11+i%3, i/3)
			mark(i/3, size-11+i%3)
		}
	}
	return m
}

// readFormat pulls the fifteen bits back out the way a reader does, most
// significant first, from one corner or the other.
func readFormat(c *Code, corner int) (level, mask int, ok bool) {
	var raw int
	take := func(x, y int) {
		raw <<= 1
		if c.Modules[y][x] {
			raw |= 1
		}
	}

	if corner == 0 {
		for x := 0; x <= 5; x++ {
			take(x, 8)
		}
		take(7, 8)
		take(8, 8)
		take(8, 7)
		for y := 5; y >= 0; y-- {
			take(8, y)
		}
	} else {
		for y := c.Size - 1; y >= c.Size-7; y-- {
			take(8, y)
		}
		for x := c.Size - 8; x < c.Size; x++ {
			take(x, 8)
		}
	}

	value := raw ^ 0b101010000010010

	// The BCH check a reader makes: a valid field leaves no remainder.
	remainder := value
	for i := 14; i >= 10; i-- {
		if remainder&(1<<uint(i)) != 0 {
			remainder ^= 0b10100110111 << uint(i-10)
		}
	}
	if remainder != 0 {
		return 0, 0, false
	}
	return value >> 13, (value >> 10) & 0b111, true
}

// readVersion pulls the eighteen-bit block out of the top-right corner.
func readVersion(c *Code) int {
	var raw int
	for i := 17; i >= 0; i-- {
		raw <<= 1
		if c.Modules[i/3][c.Size-11+i%3] {
			raw |= 1
		}
	}
	return raw >> 12
}

// readCodewords lifts the mask and walks the columns the way a reader does.
func readCodewords(c *Code, fn [][]bool, mask int) []byte {
	var bits []bool

	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vertical := 0; vertical < c.Size; vertical++ {
			for offset := 0; offset < 2; offset++ {
				x := right - offset
				y := vertical
				if (right+1)&2 == 0 {
					y = c.Size - 1 - vertical
				}
				if fn[y][x] {
					continue
				}
				dark := c.Modules[y][x]
				if maskAt(mask, x, y) {
					dark = !dark
				}
				bits = append(bits, dark)
			}
		}
	}

	out := make([]byte, len(bits)/8)
	for i := range out {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				b |= 1 << uint(7-j)
			}
		}
		out[i] = b
	}
	return out
}

// deinterleave undoes the shuffling: one block per group, data then error
// correction.
func deinterleave(stream []byte, spec versionSpec) [][]byte {
	sizes := make([]int, 0, spec.group1Blocks+spec.group2Blocks)
	for i := 0; i < spec.group1Blocks; i++ {
		sizes = append(sizes, spec.group1Data)
	}
	for i := 0; i < spec.group2Blocks; i++ {
		sizes = append(sizes, spec.group2Data)
	}

	blocks := make([][]byte, len(sizes))
	longest := 0
	for i, size := range sizes {
		blocks[i] = make([]byte, 0, size+spec.ecPerBlock)
		if size > longest {
			longest = size
		}
	}

	at := 0
	for i := 0; i < longest; i++ {
		for b, size := range sizes {
			if i < size {
				blocks[b] = append(blocks[b], stream[at])
				at++
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for b := range blocks {
			blocks[b] = append(blocks[b], stream[at])
			at++
		}
	}
	return blocks
}

// syndromesAreZero is the definition of a valid Reed-Solomon codeword: it
// vanishes at every root of the generator. How it was produced does not enter
// into it, which is what makes this worth asserting.
func syndromesAreZero(block []byte, count int) bool {
	for i := 0; i < count; i++ {
		root := expTable[i]
		var sum byte
		for _, coeff := range block {
			sum = gfMul(sum, root) ^ coeff
		}
		if sum != 0 {
			return false
		}
	}
	return true
}

// decode reads a symbol back to the text it was made from, checking on the way
// everything a scanner checks.
func decode(t *testing.T, c *Code, version int) string {
	t.Helper()
	spec := versions[version]
	fn := functionMap(version)

	free := 0
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if !fn[y][x] {
				free++
			}
		}
	}
	if want := spec.totalCodewords*8 + remainderBits[version]; free != want {
		t.Fatalf("version %d leaves %d data modules, the specification says %d",
			version, free, want)
	}

	level, mask, ok := readFormat(c, 0)
	if !ok {
		t.Fatal("the format information does not pass its own error correction")
	}
	if level != 0 {
		t.Fatalf("the format information names error correction level %d, want M", level)
	}
	if second, secondMask, ok := readFormat(c, 1); !ok || second != level || secondMask != mask {
		t.Fatal("the two copies of the format information disagree")
	}

	if version >= 7 {
		if got := readVersion(c); got != version {
			t.Fatalf("the version block reads %d on a version %d symbol", got, version)
		}
	}

	blocks := deinterleave(readCodewords(c, fn, mask), spec)
	for i, block := range blocks {
		if !syndromesAreZero(block, spec.ecPerBlock) {
			t.Fatalf("block %d is not a valid Reed-Solomon codeword", i)
		}
	}

	var data []byte
	for i, block := range blocks {
		size := spec.group1Data
		if i >= spec.group1Blocks {
			size = spec.group2Data
		}
		data = append(data, block[:size]...)
	}

	read := func(offset, count int) int {
		value := 0
		for i := 0; i < count; i++ {
			bit := offset + i
			value <<= 1
			if data[bit/8]&(1<<uint(7-bit%8)) != 0 {
				value |= 1
			}
		}
		return value
	}
	if mode := read(0, 4); mode != 0b0100 {
		t.Fatalf("the symbol announces mode %04b, want byte mode", mode)
	}
	width := countBits(version)
	length := read(4, width)

	out := make([]byte, length)
	for i := range out {
		out[i] = byte(read(4+width+i*8, 8))
	}
	return string(out)
}

// The test that would have caught it: every version this encoder can produce,
// filled to the brim, read back the way a phone reads it.
func TestEverySymbolReadsBack(t *testing.T) {
	for version := 1; version <= 10; version++ {
		spec := versions[version]

		// The longest text this version holds, so the padding, the block
		// interleaving and the count field are all exercised at their limit.
		length := spec.dataCodewords() - (4+countBits(version)+4+7)/8
		text := strings.Repeat("SYNSEC-", length/7+1)[:length]

		code, err := Encode(text)
		if err != nil {
			t.Fatalf("version %d: Encode: %v", version, err)
		}
		if code.Size != 17+4*version {
			t.Fatalf("a %d-byte text produced a %d-module symbol, want version %d",
				length, code.Size, version)
		}
		if got := decode(t, code, version); got != text {
			t.Fatalf("version %d read back %q, want %q", version, got, text)
		}
	}
}

// The address an authenticator is actually handed, end to end.
func TestTheEnrolmentAddressReadsBack(t *testing.T) {
	const uri = "otpauth://totp/SYNSEC:cyril?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" +
		"&issuer=SYNSEC&algorithm=SHA1&digits=6&period=30"

	code, err := Encode(uri)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	version := (code.Size - 17) / 4
	if version < 7 {
		t.Fatalf("the enrolment address landed on version %d, which leaves the "+
			"version block untested - lengthen the sample", version)
	}
	if got := decode(t, code, version); got != uri {
		t.Fatalf("the enrolment address read back as %q", got)
	}
}

// Level M with mask 0 is a published constant, and it is the exclusive-or mask
// itself: five zero bits of data, and the remainder of an all-zero polynomial
// is zero. Reading it back through a reader's path anchors both the code and
// where it is written.
func TestTheFormatFieldMatchesTheSpecification(t *testing.T) {
	code, err := Encode("x")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	code.drawFormat(0)

	if level, mask, ok := readFormat(code, 0); !ok || level != 0 || mask != 0 {
		t.Fatalf("level M mask 0 read back as level %d mask %d (valid: %v)", level, mask, ok)
	}
	if level, mask, ok := readFormat(code, 1); !ok || level != 0 || mask != 0 {
		t.Fatalf("the second copy read back as level %d mask %d (valid: %v)", level, mask, ok)
	}
}

// A symbol whose format field is written into the wrong cells scans and then
// fails, which is the failure that shipped. Transposing it must be caught.
func TestATransposedFormatFieldIsRejected(t *testing.T) {
	code, err := Encode("x")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Reflect the whole symbol about its diagonal. The finders and the timing
	// patterns survive that; the format field does not.
	for y := 0; y < code.Size; y++ {
		for x := y + 1; x < code.Size; x++ {
			code.Modules[y][x], code.Modules[x][y] = code.Modules[x][y], code.Modules[y][x]
		}
	}

	if _, _, ok := readFormat(code, 0); ok {
		t.Fatal("a transposed format field passed its error correction, so the " +
			"check that would have caught the shipped bug is not doing anything")
	}
}
