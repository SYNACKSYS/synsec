package crypto

import "testing"

const (
	gio = 1024 * 1024 * 1024
	mio = 1024 * 1024
)

// Les machines que le manuel d'installation recommande par leur nom, avec ce
// qu'elles ont vraiment sous le capot.
func TestLeProfilSuitLaMachine(t *testing.T) {
	cas := []struct {
		machine    string
		memoire    uint64
		concurrent int
		attendu    Argon2Params
	}{
		{"Raspberry Pi 3, 1 Gio", 1 * gio, 4, LowMemoryArgon2},
		{"Raspberry Pi Zero, 512 Mio", 512 * mio, 2, LowMemoryArgon2},
		{"Synology d'entree de gamme, 512 Mio", 512 * mio, 4, LowMemoryArgon2},
		{"Raspberry Pi 4, 4 Gio", 4 * gio, 4, DefaultArgon2},
		{"machine virtuelle a deux coeurs, 2 Gio", 2 * gio, 2, DefaultArgon2},
		{"poste de travail, 32 Gio", 32 * gio, 4, DefaultArgon2},
	}

	for _, c := range cas {
		got := paramsFor(c.memoire, c.concurrent)
		if got != c.attendu {
			t.Errorf("%s : profil %d Mio alors qu'on attendait %d Mio",
				c.machine, got.Memory/1024, c.attendu.Memory/1024)
		}
	}
}

// La pointe est ce qui décide, pas la taille de la machine seule : le même
// gigaoctet ne coûte pas la même chose selon le nombre de connexions qui
// peuvent dériver en même temps.
func TestCeQuiDecideEstLaPointeEtPasSeulementLaMemoire(t *testing.T) {
	const memoire = 2 * gio

	if p := paramsFor(memoire, 2); p != DefaultArgon2 {
		t.Errorf("deux dérivations dans 2 Gio tiennent, profil allégé inutile : %+v", p)
	}
	if p := paramsFor(memoire, 4); p != DefaultArgon2 {
		t.Errorf("quatre dérivations dans 2 Gio tiennent encore : %+v", p)
	}
	if p := paramsFor(1*gio, 4); p != LowMemoryArgon2 {
		t.Errorf("quatre dérivations dans 1 Gio ne tiennent pas : %+v", p)
	}
}

// Le profil allégé reste au-dessus du plancher que valid impose : l'alléger
// sans le vérifier produirait une machine où aucun mot de passe ne peut être
// enregistré.
func TestLeProfilAllegeResteAcceptable(t *testing.T) {
	if err := LowMemoryArgon2.valid(); err != nil {
		t.Fatalf("le profil allégé est refusé par valid : %v", err)
	}
}

// La concurrence est bornée des deux côtés : c'est elle qui borne la pointe,
// donc une valeur folle rendrait le calcul ci-dessus faux.
func TestLaConcurrenceEstBornee(t *testing.T) {
	n := DerivationConcurrency()
	if n < 2 || n > 4 {
		t.Errorf("concurrence hors des bornes attendues : %d", n)
	}
}
