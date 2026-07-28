// Package qr encodes a short text as a QR code and draws it as SVG.
//
// Written rather than imported, because a QR code is a well-specified piece of
// arithmetic and SYNSEC promises to carry no dependency. It handles what this
// server needs and nothing else: byte mode, error correction level M, and the
// smallest version that fits.
//
// A wrong code here is harmless. Enrolment only completes once the person
// types back a code their application produced, so a QR that scans badly fails
// at that step, visibly, with the typed key still available beside it.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a finished symbol: size modules across, dark where true.
type Code struct {
	Size    int
	Modules [][]bool
}

// Encode builds the smallest level-M symbol that holds the text.
func Encode(text string) (*Code, error) {
	data := []byte(text)

	version, err := smallestVersion(len(data))
	if err != nil {
		return nil, err
	}
	spec := versions[version]

	bits := encodeData(data, version)
	codewords := assemble(bits, spec)

	size := 17 + 4*version
	c := &Code{Size: size, Modules: make([][]bool, size)}
	reserved := make([][]bool, size)
	for i := range c.Modules {
		c.Modules[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}

	c.drawFunctionPatterns(version, reserved)
	c.drawCodewords(codewords, reserved)

	mask := c.chooseMask(reserved)
	c.applyMask(mask, reserved)
	c.drawFormat(mask)
	return c, nil
}

// SVG draws the code, sized in CSS pixels, with a quiet zone.
//
// One path of rectangles rather than one element per module: a version 4
// symbol is over a thousand modules, and a thousand elements is a page that
// takes longer to lay out than to fetch.
func (c *Code) SVG(pixels int, class string) string {
	const quiet = 4
	total := c.Size + 2*quiet

	var path strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Modules[y][x] {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}

	return fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" class="%s" width="%d" height="%d" `+
			`viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" `+
			`aria-label="Code QR de configuration">`+
			`<rect width="%d" height="%d" fill="#ffffff"/>`+
			`<path d="%s" fill="#000000"/></svg>`,
		class, pixels, pixels, total, total, total, total, path.String())
}

// versionSpec is what one version needs: total codewords, and how the error
// correction blocks are cut up at level M.
type versionSpec struct {
	totalCodewords int
	ecPerBlock     int
	group1Blocks   int
	group1Data     int
	group2Blocks   int
	group2Data     int
	alignment      []int
}

// Versions 1 to 10 at level M. An otpauth address runs to about 120 bytes,
// which version 6 holds comfortably; the rest is headroom for a long account
// name.
var versions = map[int]versionSpec{
	1:  {26, 10, 1, 16, 0, 0, nil},
	2:  {44, 16, 1, 28, 0, 0, []int{6, 18}},
	3:  {70, 26, 1, 44, 0, 0, []int{6, 22}},
	4:  {100, 18, 2, 32, 0, 0, []int{6, 26}},
	5:  {134, 24, 2, 43, 0, 0, []int{6, 30}},
	6:  {172, 16, 4, 27, 0, 0, []int{6, 34}},
	7:  {196, 18, 4, 31, 0, 0, []int{6, 22, 38}},
	8:  {242, 22, 2, 38, 2, 39, []int{6, 24, 42}},
	9:  {292, 22, 3, 36, 2, 37, []int{6, 26, 46}},
	10: {346, 26, 4, 43, 1, 44, []int{6, 28, 50}},
}

func (v versionSpec) dataCodewords() int {
	return v.group1Blocks*v.group1Data + v.group2Blocks*v.group2Data
}

// countBits is the width of the character count that follows the mode.
//
// Byte mode uses eight bits up to version 9 and sixteen from version 10. Get
// this wrong and every bit after it is off by eight, which is a symbol that
// scans perfectly and decodes to rubbish.
func countBits(version int) int {
	if version >= 10 {
		return 16
	}
	return 8
}

func smallestVersion(length int) (int, error) {
	for version := 1; version <= 10; version++ {
		spec := versions[version]
		// Four bits of mode, the count, and four of terminator.
		if spec.dataCodewords()*8 >= length*8+4+countBits(version)+4 {
			return version, nil
		}
	}
	return 0, errors.New("qr: text too long for this encoder")
}

// encodeData writes the bit stream: mode, length, bytes, terminator, padding.
func encodeData(data []byte, version int) []bool {
	spec := versions[version]
	capacity := spec.dataCodewords() * 8

	var bits []bool
	appendBits := func(value, count int) {
		for i := count - 1; i >= 0; i-- {
			bits = append(bits, value&(1<<uint(i)) != 0)
		}
	}

	appendBits(0b0100, 4) // byte mode
	appendBits(len(data), countBits(version))
	for _, b := range data {
		appendBits(int(b), 8)
	}

	// Terminator, then pad to a byte boundary, then the two alternating pad
	// bytes the specification names.
	for i := 0; i < 4 && len(bits) < capacity; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for i := 0; len(bits) < capacity; i++ {
		if i%2 == 0 {
			appendBits(0xEC, 8)
		} else {
			appendBits(0x11, 8)
		}
	}
	return bits
}

// assemble cuts the data into blocks, computes their error correction, and
// interleaves both the way the specification requires.
func assemble(bits []bool, spec versionSpec) []byte {
	data := make([]byte, len(bits)/8)
	for i := range data {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				b |= 1 << uint(7-j)
			}
		}
		data[i] = b
	}

	blocks := make([][]byte, 0, spec.group1Blocks+spec.group2Blocks)
	ecBlocks := make([][]byte, 0, cap(blocks))

	offset := 0
	take := func(count, size int) {
		for i := 0; i < count; i++ {
			block := data[offset : offset+size]
			offset += size
			blocks = append(blocks, block)
			ecBlocks = append(ecBlocks, reedSolomon(block, spec.ecPerBlock))
		}
	}
	take(spec.group1Blocks, spec.group1Data)
	take(spec.group2Blocks, spec.group2Data)

	var out []byte
	longest := spec.group1Data
	if spec.group2Data > longest {
		longest = spec.group2Data
	}
	for i := 0; i < longest; i++ {
		for _, block := range blocks {
			if i < len(block) {
				out = append(out, block[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, block := range ecBlocks {
			out = append(out, block[i])
		}
	}
	return out
}
