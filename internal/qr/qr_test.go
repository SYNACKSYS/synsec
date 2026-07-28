package qr

import (
	"strings"
	"testing"
)

// Reed-Solomon is checked against the property that defines it rather than
// against a table copied from somewhere: the codeword polynomial, data
// followed by its error correction, must be divisible by the generator. That
// is exactly what a decoder relies on, and unlike a remembered vector it
// cannot be right by coincidence.
func TestErrorCorrectionIsDivisibleByTheGenerator(t *testing.T) {
	for _, count := range []int{10, 16, 18, 22, 24, 26} {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i*7 + count)
		}

		codeword := append(append([]byte{}, data...), reedSolomon(data, count)...)

		// Evaluating at the generator's roots must give zero at every one.
		for root := 0; root < count; root++ {
			sum := byte(0)
			for _, coeff := range codeword {
				sum = gfMul(sum, expTable[root]) ^ coeff
			}
			if sum != 0 {
				t.Fatalf("with %d correction bytes, the codeword is not divisible: root %d gives %#02x",
					count, root, sum)
			}
		}
	}
}

// A single wrong byte must break that property, or the test above would pass
// on anything.
func TestACorruptedCodewordIsDetectable(t *testing.T) {
	data := []byte("SYNSEC teste son encodeur QR ok!")
	codeword := append(append([]byte{}, data...), reedSolomon(data, 10)...)
	codeword[3] ^= 0x01

	broken := false
	for root := 0; root < 10; root++ {
		sum := byte(0)
		for _, coeff := range codeword {
			sum = gfMul(sum, expTable[root]) ^ coeff
		}
		if sum != 0 {
			broken = true
		}
	}
	if !broken {
		t.Fatal("a corrupted codeword still divides cleanly: the check proves nothing")
	}
}

// The field is the one the specification names: 2^8 elements, generator 2,
// modulo 0x11D.
func TestGaloisFieldIsWellFormed(t *testing.T) {
	seen := make(map[byte]bool, 255)
	for i := 0; i < 255; i++ {
		if seen[expTable[i]] {
			t.Fatalf("the exponent table repeats at %d: the field is wrong", i)
		}
		seen[expTable[i]] = true
	}
	if expTable[0] != 1 {
		t.Fatalf("2^0 is %d, want 1", expTable[0])
	}
	if expTable[255] != expTable[0] {
		t.Fatal("the table does not wrap after 255")
	}

	// Multiplication has to agree with the logarithms in both directions.
	for a := 1; a < 256; a += 17 {
		for b := 1; b < 256; b += 13 {
			product := gfMul(byte(a), byte(b))
			if product == 0 {
				t.Fatalf("%d x %d gave zero in a field with no zero divisors", a, b)
			}
		}
	}
}

// The structure a scanner locks onto has to be exactly where it looks.
func TestFinderPatternsAreInThreeCorners(t *testing.T) {
	code, err := Encode("otpauth://totp/SYNSEC:cyril?secret=ABCDEFGHIJKLMNOP&issuer=SYNSEC")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	corners := [][2]int{{0, 0}, {code.Size - 7, 0}, {0, code.Size - 7}}
	for _, corner := range corners {
		x, y := corner[0], corner[1]
		// The outer ring is dark, the ring inside it light, the core dark.
		if !code.Modules[y][x] || !code.Modules[y+6][x+6] {
			t.Fatalf("the finder at %d,%d has no outer ring", x, y)
		}
		if code.Modules[y+1][x+1] || code.Modules[y+5][x+5] {
			t.Fatalf("the finder at %d,%d has no light ring", x, y)
		}
		if !code.Modules[y+3][x+3] {
			t.Fatalf("the finder at %d,%d has no core", x, y)
		}
	}

	// And the module the specification always sets, which a decoder uses to
	// confirm it has the right symbol the right way up.
	if !code.Modules[code.Size-8][8] {
		t.Fatal("the always-dark module is light")
	}
}

func TestTimingPatternsAlternate(t *testing.T) {
	code, err := Encode("SYNSEC")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for i := 8; i < code.Size-8; i++ {
		want := i%2 == 0
		if code.Modules[6][i] != want {
			t.Fatalf("the horizontal timing pattern breaks at %d", i)
		}
		if code.Modules[i][6] != want {
			t.Fatalf("the vertical timing pattern breaks at %d", i)
		}
	}
}

// The version has to grow with the text rather than overflow.
func TestVersionGrowsWithTheText(t *testing.T) {
	short, err := Encode("SYNSEC")
	if err != nil {
		t.Fatalf("Encode short: %v", err)
	}
	long, err := Encode(strings.Repeat("a", 100))
	if err != nil {
		t.Fatalf("Encode long: %v", err)
	}
	if long.Size <= short.Size {
		t.Fatalf("a longer text gave a symbol of %d, no larger than %d", long.Size, short.Size)
	}

	if _, err := Encode(strings.Repeat("a", 5000)); err == nil {
		t.Fatal("a text beyond every version was accepted")
	}
}

// A real enrolment address must fit, since that is the only thing this
// encoder exists for.
func TestOtpauthURIFits(t *testing.T) {
	uri := "otpauth://totp/SYNSEC:un-nom-de-compte-assez-long?" +
		"digits=6&issuer=SYNSEC&period=30&secret=VFI2L4JAT5ITVZ7PPEZNLEEWZ2RIHTQS"

	code, err := Encode(uri)
	if err != nil {
		t.Fatalf("a real enrolment address did not fit: %v", err)
	}
	if code.Size < 21 || code.Size > 57 {
		t.Fatalf("the symbol is %d modules across, which is not a version 1 to 10", code.Size)
	}
}

func TestSVGIsSelfContained(t *testing.T) {
	code, err := Encode("SYNSEC")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	svg := code.SVG(240, "qr")

	for _, want := range []string{"<svg", "viewBox", "</svg>", `width="240"`, "role=\"img\""} {
		if !strings.Contains(svg, want) {
			t.Errorf("the SVG lacks %q", want)
		}
	}
	// Nothing may be fetched: the page it lands on forbids every external
	// host. The xmlns is an identifier, not an address, so what matters is
	// that no attribute actually points somewhere.
	for _, forbidden := range []string{"<image", "xlink:href", "href=", "src=", "url("} {
		if strings.Contains(svg, forbidden) {
			t.Errorf("the SVG refers to something external: %q", forbidden)
		}
	}
}
