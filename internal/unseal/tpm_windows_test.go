//go:build windows

package unseal

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Le TPM ne se simule pas. Ces tests sautent sur une machine sans puce, et
// c'est délibéré : un test qui passerait sans matériel ne prouverait rien de
// ce que ce fichier promet.
//
// Ils travaillent sur une clé d'utilisateur, pas de machine : une clé de
// machine demande des droits administrateur, que la suite de tests n'a pas et
// ne doit pas réclamer. Tout le reste est identique - même puce, même clé RSA
// persistée, même OAEP, même double passe. Ce qui n'est donc pas couvert ici
// tient en un drapeau, et se vérifie à l'installation.
func requireTPM(t *testing.T) tpmSession {
	t.Helper()
	if !windowsTPMAvailable() {
		t.Skip("aucun TPM sur cette machine")
	}
	return tpmSession{}
}

// tpmSession rejoue Protect et Expose avec les droits dont dispose un test.
type tpmSession struct{}

const testKeyFlags = ncryptSilentFlag

func (tpmSession) Protect(key []byte) ([]byte, error) {
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	handle, err := openOrCreateKey(prov, testKeyFlags)
	if err != nil {
		return nil, err
	}
	defer freeObject(handle)

	return oaep(procEncrypt, handle, key, "chiffrement")
}

func (tpmSession) Expose(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, ErrNoHandle
	}
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	key, err := openKey(prov, testKeyFlags)
	if err != nil {
		return nil, err
	}
	defer freeObject(key)

	return oaep(procDecrypt, key, blob, "déchiffrement")
}

func TestTheChipSealsAndReopens(t *testing.T) {
	tpm := requireTPM(t)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}

	handle, err := tpm.Protect(key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if len(handle) == 0 {
		t.Fatal("le blob est vide")
	}
	// Ce qui est rangé ne doit contenir la clé nulle part : c'est la seule
	// chose que le disque verra.
	if bytes.Contains(handle, key) {
		t.Fatal("la clé apparaît en clair dans le blob")
	}

	back, err := tpm.Expose(handle)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	if !bytes.Equal(back, key) {
		t.Fatalf("relue différente : %x vs %x", back, key)
	}
}

// Deux scellements de la même clé donnent deux blobs différents : OAEP tire un
// aléa à chaque fois. Sans ça, comparer deux bases dirait si elles portent la
// même clé racine.
func TestTwoSealsOfTheSameKeyDiffer(t *testing.T) {
	tpm := requireTPM(t)

	key := bytes.Repeat([]byte{7}, 32)
	first, err := tpm.Protect(key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	second, err := tpm.Protect(key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("deux scellements identiques")
	}

	// Et les deux se rouvrent, donc la clé de la puce a bien été réutilisée
	// plutôt que régénérée au passage - ce qui aurait rendu le premier blob
	// définitivement illisible.
	for i, blob := range [][]byte{first, second} {
		back, err := tpm.Expose(blob)
		if err != nil {
			t.Fatalf("Expose du blob %d : %v", i, err)
		}
		if !bytes.Equal(back, key) {
			t.Fatalf("blob %d rouvert différent", i)
		}
	}
}

func TestAnAlteredBlobIsRefused(t *testing.T) {
	tpm := requireTPM(t)

	key := bytes.Repeat([]byte{3}, 32)
	handle, err := tpm.Protect(key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	handle[len(handle)/2] ^= 0xff
	if _, err := tpm.Expose(handle); err == nil {
		t.Fatal("un blob modifié a été accepté")
	}
}

func TestNoHandleIsAnError(t *testing.T) {
	tpm := requireTPM(t)
	if _, err := tpm.Expose(nil); err == nil {
		t.Fatal("un blob absent a été accepté")
	}
}

// Ce que le fournisseur annonce doit correspondre à ce qu'il fait, parce que
// c'est ce texte que l'installation affiche au propriétaire.
func TestWhatTheChipClaims(t *testing.T) {
	p := WindowsTPM{}.Protection()
	if !p.ResistsDiskTheft {
		t.Error("le TPM devrait résister au vol de disque")
	}
	if p.Summary == "" || p.Caveat == "" {
		t.Error("il manque le résumé ou la réserve")
	}
	if name := (WindowsTPM{}).Name(); name != "windows-tpm" {
		t.Errorf("nom = %q", name)
	}
}

// La liste d'accès est ce qui décide si le service redémarre : elle donne la
// clé à LocalSystem, sous lequel tourne SYNSEC, alors que la clé est créée par
// la personne qui lance l'installation dans une invite élevée.
//
// Le test la pose sur une clé d'utilisateur, faute des droits nécessaires à
// une clé de machine. Ce qu'il prouve : la traduction du SDDL et la forme de
// l'appel à CNG. Ce qu'il ne prouve pas : que LocalSystem ouvre effectivement
// la clé de production, ce qui se vérifie en redémarrant le service.
func TestTheKeyAcceptsItsAccessList(t *testing.T) {
	requireTPM(t)

	prov, err := openPlatformProvider()
	if err != nil {
		t.Fatalf("openPlatformProvider: %v", err)
	}
	defer freeObject(prov)

	key, err := openOrCreateKey(prov, testKeyFlags)
	if err != nil {
		t.Fatalf("openOrCreateKey: %v", err)
	}
	defer freeObject(key)

	if err := grantServiceAccess(key); err != nil {
		t.Fatalf("grantServiceAccess: %v", err)
	}
}
