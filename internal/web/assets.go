package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"sort"
)

// Making sure a browser picks up a new interface.
//
// The style sheet and the scripts are embedded, so they change exactly when
// the binary changes - and they are cached hard, because they are the same
// bytes on every request for the life of a version. Both statements are true
// and together they were a trap: the address never changed either, so a phone
// that had visited once kept the old presentation for a day after an upgrade,
// and the owner concluded the upgrade had done nothing.
//
// So the address carries a fingerprint of what it points at. New bytes, new
// address, fetched at once. Same bytes, same address, not fetched at all -
// which is the point of caching in the first place.

// assetTag hashes every embedded asset into a short label for the query
// string.
//
// The content rather than the version number: a build made between two
// releases changes the files without changing the version, and that build is
// precisely the one somebody is testing.
func assetTag() (string, error) {
	var names []string
	err := fs.WalkDir(assets, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	// Sorted, so the same set of files always yields the same label whatever
	// order the walk happened to take.
	sort.Strings(names)

	sum := sha256.New()
	for _, name := range names {
		content, err := fs.ReadFile(assets, name)
		if err != nil {
			return "", err
		}
		sum.Write([]byte(name))
		sum.Write([]byte{0})
		sum.Write(content)
	}
	// Eight hex characters: enough that two different interfaces will not
	// collide in the life of this project, short enough to read in a log.
	return hex.EncodeToString(sum.Sum(nil))[:8], nil
}

// navSection says which group of the menu holds a page.
//
// Decided here rather than in the template: the mapping is a fact about the
// interface, and a chain of comparisons repeated in markup is the kind of
// thing that drifts the day a page is added.
func navSection(nav string) string {
	switch nav {
	case "coffres", "recherche":
		return "coffres"
	case "parametres", "motdepasse", "deuxfacteurs", "cles":
		return "parametres"
	case "comptes", "serveur", "alertes", "journal":
		return "administration"
	}
	// An unknown page - a secret, a vault, an import - belongs to the vaults,
	// which is where its reader came from and where they will go next.
	return "coffres"
}
