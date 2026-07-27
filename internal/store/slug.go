package store

import "strings"

// Slugify turns a label someone typed into the identifier that addresses it.
//
// "Mot de passe MQTT" becomes mot_de_passe_mqtt, "Clé Zigbee" becomes
// cle_zigbee. The result is what a device asks for and what goes into the
// encryption, so it has to be stable, lowercase and free of anything that
// would need escaping in a URL, a shell or a configuration file.
//
// Deliberately not reversible: the label remains the thing people read, and it
// is kept alongside rather than reconstructed from the slug.
func Slugify(label string) string {
	var b strings.Builder
	b.Grow(len(label))

	lastSeparator := true // trims any leading separator
	for _, r := range label {
		switch folded := foldAccent(r); {
		case folded >= 'a' && folded <= 'z', folded >= '0' && folded <= '9':
			b.WriteRune(folded)
			lastSeparator = false
		case folded >= 'A' && folded <= 'Z':
			b.WriteRune(folded + 32)
			lastSeparator = false
		case !lastSeparator:
			// Anything else collapses to a single underscore, so "clé - wifi"
			// does not come out riddled with them.
			b.WriteByte('_')
			lastSeparator = true
		}
	}

	slug := strings.TrimSuffix(b.String(), "_")
	if slug == "" {
		return ""
	}
	if len(slug) > MaxSecretNameLength {
		slug = strings.TrimSuffix(slug[:MaxSecretNameLength], "_")
	}
	return slug
}

// foldAccent maps an accented Latin letter onto its plain form.
//
// A table rather than Unicode normalisation: the alternative pulls in
// golang.org/x/text for a job that, in French, comes down to these few dozen
// runes. A letter it does not know becomes a separator, which is the right
// outcome for anything that is not a letter at all.
func foldAccent(r rune) rune {
	switch r {
	case 'à', 'á', 'â', 'ã', 'ä', 'å':
		return 'a'
	case 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å':
		return 'A'
	case 'ç':
		return 'c'
	case 'Ç':
		return 'C'
	case 'è', 'é', 'ê', 'ë':
		return 'e'
	case 'È', 'É', 'Ê', 'Ë':
		return 'E'
	case 'ì', 'í', 'î', 'ï':
		return 'i'
	case 'Ì', 'Í', 'Î', 'Ï':
		return 'I'
	case 'ñ':
		return 'n'
	case 'Ñ':
		return 'N'
	case 'ò', 'ó', 'ô', 'õ', 'ö':
		return 'o'
	case 'Ò', 'Ó', 'Ô', 'Õ', 'Ö':
		return 'O'
	case 'ù', 'ú', 'û', 'ü':
		return 'u'
	case 'Ù', 'Ú', 'Û', 'Ü':
		return 'U'
	case 'ý', 'ÿ':
		return 'y'
	case 'Ý', 'Ÿ':
		return 'Y'
	default:
		return r
	}
}

// UniqueSlug returns a slug not already taken in the vault, adding a numeric
// suffix if it has to.
//
// Two secrets can reasonably be called "Mot de passe" in the same vault, and
// refusing the second would be pedantic. The suffix is applied to the slug
// alone; both keep the label their owner chose.
func UniqueSlug(label string, taken map[string]bool) string {
	base := Slugify(label)
	if base == "" {
		base = "secret"
	}
	if !taken[base] {
		return base
	}

	for n := 2; ; n++ {
		candidate := base + "_" + itoa(n)
		if !taken[candidate] {
			return candidate
		}
	}
}

// itoa avoids pulling in strconv for numbers that never exceed a handful of
// digits.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 && i > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
