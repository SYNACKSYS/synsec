package vault

import (
	"context"
	"path/filepath"
	"testing"

	"synsec/internal/store"
	"synsec/internal/unseal"
)

// Re-sceller, c'est déplacer la garde de la clé racine d'un fournisseur à un
// autre sans perdre un seul secret.
//
// Le test ne dépend d'aucun matériel : il vérifie que le fournisseur inscrit
// dans le slot est bien celui que la machine sait offrir, que le coffre se
// rouvre après l'opération, et que les secrets déjà rangés se relisent. Ce
// sont les trois choses qui casseraient si la migration était fausse.

func TestResealingKeepsTheVaultOpenable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "synsec.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	m := New(db, dir)
	if _, err := m.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Un secret rangé avant la migration : c'est lui qui dira si la clé
	// racine a survécu au passage.
	projet, err := m.CreateVault(ctx, "Maison", "", "")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	loc := store.SecretLocation{ProjectID: projet.ID, Env: store.DefaultEnvironment, Name: "mqtt"}
	if _, err := m.PutSecret(ctx, loc, []byte("s3cr3t"), "MQTT", "cyril"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	avant, err := m.CurrentProvider(ctx)
	if err != nil {
		t.Fatalf("CurrentProvider: %v", err)
	}

	provider, err := m.ReprovisionMachineSlot(ctx)
	if err != nil {
		t.Fatalf("ReprovisionMachineSlot: %v", err)
	}

	apres, err := m.CurrentProvider(ctx)
	if err != nil {
		t.Fatalf("CurrentProvider: %v", err)
	}
	if apres != provider.Name() {
		t.Fatalf("le slot dit %q, le re-scellement a rendu %q", apres, provider.Name())
	}

	// Ce que le prochain démarrage fera : refermer, rouvrir avec ce qui vient
	// d'être écrit.
	m.Seal()
	if err := m.Unseal(ctx); err != nil {
		t.Fatalf("le coffre ne se rouvre pas après re-scellement (%s -> %s) : %v", avant, apres, err)
	}

	valeur, err := m.GetSecret(ctx, loc)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(valeur) != "s3cr3t" {
		t.Fatalf("le secret a changé : %q", valeur)
	}
}

// Le meta ne doit pas rester sur l'ancien nom : il est lu par un humain qui
// diagnostique, et un diagnostic sur une valeur périmée coûte une soirée.
func TestResealingUpdatesTheRecordedName(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "synsec.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	m := New(db, dir)
	if _, err := m.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	provider, err := m.ReprovisionMachineSlot(ctx)
	if err != nil {
		t.Fatalf("ReprovisionMachineSlot: %v", err)
	}

	meta, err := db.Meta(ctx, metaUnsealProvider)
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if string(meta) != provider.Name() {
		t.Fatalf("le meta dit %q, le fournisseur est %q", meta, provider.Name())
	}
}

// Ce que la machine sait offrir aujourd'hui doit être un fournisseur que
// l'ouverture sait retrouver. Sans ça, une installation neuve démarrerait une
// fois puis échouerait au redémarrage suivant.
func TestTheBestProviderIsOneThatCanBeReopened(t *testing.T) {
	dir := t.TempDir()
	m := New(nil, dir)

	best := m.BestProvider()
	if best.Name() == "" {
		t.Fatal("aucun fournisseur détecté")
	}
	if _, err := unseal.ByName(best.Name(), dir); err != nil {
		t.Fatalf("le fournisseur détecté %q n'est pas retrouvable : %v", best.Name(), err)
	}
}
