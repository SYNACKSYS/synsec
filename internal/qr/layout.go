package qr

// Module placement: the patterns a scanner looks for, then the data woven
// around them, then the mask that keeps the result from looking like one of
// those patterns by accident.

// drawFunctionPatterns lays down everything that is not data, and marks those
// positions as reserved so the data placement steps over them.
func (c *Code) drawFunctionPatterns(version int, reserved [][]bool) {
	last := c.Size - 7

	// The three corner squares a scanner locks onto, with their separators.
	for _, p := range [][2]int{{0, 0}, {last, 0}, {0, last}} {
		c.drawFinder(p[0], p[1], reserved)
	}

	// Timing patterns: the alternating row and column that tell a scanner how
	// wide a module is.
	for i := 8; i < c.Size-8; i++ {
		dark := i%2 == 0
		c.set(i, 6, dark, reserved)
		c.set(6, i, dark, reserved)
	}

	for _, x := range versions[version].alignment {
		for _, y := range versions[version].alignment {
			// The alignment patterns never sit on top of a finder.
			if (x == 6 && y == 6) || (x == 6 && y == last) || (x == last && y == 6) {
				continue
			}
			c.drawAlignment(x, y, reserved)
		}
	}

	// One module that is always dark, for reasons the specification does not
	// explain and every encoder honours.
	c.set(8, c.Size-8, true, reserved)

	// The format area is reserved now and written once the mask is chosen.
	for i := 0; i < 9; i++ {
		c.reserve(i, 8, reserved)
		c.reserve(8, i, reserved)
	}
	for i := 0; i < 8; i++ {
		c.reserve(c.Size-1-i, 8, reserved)
		c.reserve(8, c.Size-1-i, reserved)
	}

	// From version 7 the size can no longer be read from the symbol's own
	// dimensions alone, so it is written out: eighteen bits, twice, in two
	// blocks beside the top-right and bottom-left finders.
	if version >= 7 {
		c.drawVersion(version, reserved)
	}
}

// drawVersion writes the version information block, protected by a BCH code.
//
// Unlike the format information there is no mask to apply afterwards: the
// value depends only on the version, so it is drawn here with the rest of the
// function patterns.
func (c *Code) drawVersion(version int, reserved [][]bool) {
	// BCH(18,6): the remainder of the version shifted up by twelve, divided by
	// x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1.
	remainder := version
	for i := 0; i < 12; i++ {
		shifted := remainder << 1
		if remainder&(1<<11) != 0 {
			shifted ^= 0x1F25
		}
		remainder = shifted
	}
	bits := version<<12 | remainder

	for i := 0; i < 18; i++ {
		dark := bits&(1<<uint(i)) != 0
		near, far := i/3, c.Size-11+i%3

		// The same eighteen bits twice: a three-wide block under the top-right
		// finder, and its mirror to the right of the bottom-left one.
		c.set(far, near, dark, reserved)
		c.set(near, far, dark, reserved)
	}
}

func (c *Code) drawFinder(x, y int, reserved [][]bool) {
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			px, py := x+dx, y+dy
			if px < 0 || py < 0 || px >= c.Size || py >= c.Size {
				continue
			}
			// A seven-wide ring, a gap, and a three-wide core.
			edge := max(abs(dx-3), abs(dy-3))
			c.set(px, py, edge != 2 && edge <= 3, reserved)
		}
	}
}

func (c *Code) drawAlignment(x, y int, reserved [][]bool) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			edge := max(abs(dx), abs(dy))
			c.set(x+dx, y+dy, edge != 1, reserved)
		}
	}
}

// drawCodewords walks the two-module-wide columns from the bottom right,
// upwards then downwards, skipping everything reserved.
func (c *Code) drawCodewords(codewords []byte, reserved [][]bool) {
	bit := 0
	total := len(codewords) * 8

	for right := c.Size - 1; right >= 1; right -= 2 {
		// The vertical timing pattern occupies column 6, so the columns to its
		// left are all shifted by one.
		if right == 6 {
			right = 5
		}
		for vertical := 0; vertical < c.Size; vertical++ {
			for offset := 0; offset < 2; offset++ {
				x := right - offset
				upward := ((right + 1) & 2) == 0
				y := vertical
				if upward {
					y = c.Size - 1 - vertical
				}
				if reserved[y][x] {
					continue
				}
				if bit < total {
					c.Modules[y][x] = codewords[bit/8]&(1<<uint(7-bit%8)) != 0
					bit++
				}
			}
		}
	}
}

// chooseMask tries all eight and keeps the one the specification's penalty
// rules like best.
func (c *Code) chooseMask(reserved [][]bool) int {
	best, bestScore := 0, -1

	for mask := 0; mask < 8; mask++ {
		c.applyMask(mask, reserved)
		c.drawFormat(mask)
		score := c.penalty()
		c.applyMask(mask, reserved) // masking twice restores the original

		if bestScore < 0 || score < bestScore {
			best, bestScore = mask, score
		}
	}
	return best
}

func (c *Code) applyMask(mask int, reserved [][]bool) {
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if reserved[y][x] || !maskAt(mask, x, y) {
				continue
			}
			c.Modules[y][x] = !c.Modules[y][x]
		}
	}
}

func maskAt(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (x*y)%2+(x*y)%3 == 0
	case 6:
		return ((x*y)%2+(x*y)%3)%2 == 0
	default:
		return ((x+y)%2+(x*y)%3)%2 == 0
	}
}

// drawFormat writes the error correction level and mask, twice, protected by a
// BCH code. Level M is 0b00.
func (c *Code) drawFormat(mask int) {
	value := 0b00<<3 | mask

	// BCH(15,5), then the fixed mask the specification applies so the field is
	// never all zeroes.
	remainder := value << 10
	for i := 14; i >= 10; i-- {
		if remainder&(1<<uint(i)) != 0 {
			remainder ^= 0b10100110111 << uint(i-10)
		}
	}
	format := ((value << 10) | remainder) ^ 0b101010000010010

	bitAt := func(i int) bool { return format&(1<<uint(i)) != 0 }

	// The copy around the top-left finder: the low bits run down column 8,
	// then the sequence turns the corner and runs left along row 8.
	//
	// Which way round matters, and is the one thing here a wrong symbol will
	// not tell you about: a reader that cannot make sense of this field cannot
	// find the mask, and gives up before looking at any data at all.
	for i := 0; i <= 5; i++ {
		c.Modules[i][8] = bitAt(i)
	}
	c.Modules[7][8] = bitAt(6)
	c.Modules[8][8] = bitAt(7)
	c.Modules[8][7] = bitAt(8)
	for i := 9; i <= 14; i++ {
		c.Modules[8][14-i] = bitAt(i)
	}

	// And the copy split between the other two: the low bits along row 8 at
	// the right, the high bits down column 8 at the bottom.
	for i := 0; i <= 7; i++ {
		c.Modules[8][c.Size-1-i] = bitAt(i)
	}
	for i := 8; i <= 14; i++ {
		c.Modules[c.Size-15+i][8] = bitAt(i)
	}
}

// penalty scores a masked symbol. Lower is better; the four rules discourage
// the shapes that make a scanner hesitate.
func (c *Code) penalty() int {
	score := 0

	// Runs of five or more of the same colour, in both directions.
	for i := 0; i < c.Size; i++ {
		score += runPenalty(c.row(i)) + runPenalty(c.column(i))
	}

	// Blocks of two by two.
	for y := 0; y < c.Size-1; y++ {
		for x := 0; x < c.Size-1; x++ {
			v := c.Modules[y][x]
			if v == c.Modules[y][x+1] && v == c.Modules[y+1][x] && v == c.Modules[y+1][x+1] {
				score += 3
			}
		}
	}

	// The finder-like sequence, which must not appear in the data.
	pattern := []bool{true, false, true, true, true, false, true, false, false, false, false}
	for i := 0; i < c.Size; i++ {
		score += 40 * (countPattern(c.row(i), pattern) + countPattern(c.column(i), pattern))
	}

	// And an imbalance between dark and light.
	dark := 0
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Modules[y][x] {
				dark++
			}
		}
	}
	percent := dark * 100 / (c.Size * c.Size)
	deviation := abs(percent-50) / 5
	score += deviation * 10

	return score
}

func runPenalty(line []bool) int {
	score, run := 0, 1
	for i := 1; i < len(line); i++ {
		if line[i] == line[i-1] {
			run++
			continue
		}
		if run >= 5 {
			score += 3 + (run - 5)
		}
		run = 1
	}
	if run >= 5 {
		score += 3 + (run - 5)
	}
	return score
}

func countPattern(line, pattern []bool) int {
	count := 0
	for i := 0; i+len(pattern) <= len(line); i++ {
		match := true
		for j, want := range pattern {
			if line[i+j] != want {
				match = false
				break
			}
		}
		if match {
			count++
		}
	}
	return count
}

func (c *Code) row(y int) []bool { return c.Modules[y] }

func (c *Code) column(x int) []bool {
	out := make([]bool, c.Size)
	for y := 0; y < c.Size; y++ {
		out[y] = c.Modules[y][x]
	}
	return out
}

func (c *Code) set(x, y int, dark bool, reserved [][]bool) {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return
	}
	c.Modules[y][x] = dark
	reserved[y][x] = true
}

func (c *Code) reserve(x, y int, reserved [][]bool) {
	if x >= 0 && y >= 0 && x < c.Size && y < c.Size {
		reserved[y][x] = true
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
