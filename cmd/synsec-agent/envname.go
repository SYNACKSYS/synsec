package main

import "strings"

// envName turns a secret identifier into an environment variable name.
//
//	mot_de_passe_mqtt  ->  MOT_DE_PASSE_MQTT
//	cle-wifi           ->  CLE_WIFI
//
// Uppercase with underscores because that is what every shell, service manager
// and language runtime expects, and because a variable whose name needs
// quoting is a variable nobody can read back.
func envName(prefix, secret string) string {
	var b strings.Builder
	b.Grow(len(prefix) + len(secret))
	b.WriteString(prefix)

	lastUnderscore := false
	for _, r := range secret {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}

	name := strings.Trim(b.String(), "_")
	if name == "" {
		return ""
	}
	// A name cannot start with a digit in any shell worth supporting.
	if name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return name
}

// collide reports two secrets that would land on the same variable.
//
// Worth naming rather than letting one silently win: "mqtt-password" and
// "mqtt_password" are different secrets and the same variable, and a service
// that quietly received the wrong one would be very hard to debug.
func collide(prefix string, names []string) (string, string, bool) {
	seen := make(map[string]string, len(names))
	for _, name := range names {
		env := envName(prefix, name)
		if env == "" {
			continue
		}
		if first, ok := seen[env]; ok {
			return first, name, true
		}
		seen[env] = name
	}
	return "", "", false
}
