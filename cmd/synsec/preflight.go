package main

import (
	"errors"
	"fmt"
	"strings"

	"synsec/internal/unseal"
)

// Ce qu'on vérifie avant de créer quoi que ce soit.
//
// L'ordre compte. Une installation qui crée le coffre, imprime le code de
// récupération, puis annonce en bas de page qu'elle a pris une protection plus
// faible que possible, arrive trop tard : la personne a déjà rangé sa feuille
// et considère l'affaire close.
//
// Donc, dans cet ordre : le contexte de la fenêtre, puis la puce, puis
// l'annonce de ce qui va être fait. Rien n'est écrit sur le disque avant que
// tout ça ait été dit.

// preflight annonce la protection qui sera utilisée, et refuse quand la
// fenêtre ne permet pas d'obtenir celle que la machine offre.
//
// forcer laisse passer une installation délibérément dégradée, pour la machine
// où l'élévation est impossible et où on préfère un serveur qui tourne.
func preflight(dataDir string, forcer bool) error {
	line := strings.Repeat("=", 66)
	fmt.Println()
	fmt.Println(line)
	fmt.Println("  Protection de la clé")
	fmt.Println(line)
	fmt.Println()

	// 1. Le contexte de la fenêtre. Sans les droits, la puce est hors de
	//    portée quoi qu'il arrive, et le reste du diagnostic ne sert à rien.
	if !isElevated() {
		fmt.Println("  Fenêtre    : sans droits administrateur")
		fmt.Println()
		if !forcer {
			return errors.New(strings.TrimSpace(`
sceller la clé dans la puce demande une invite administrateur.

        Ferme cette fenêtre, rouvre-la avec « Exécuter en tant
        qu'administrateur », et relance la commande. L'installation du
        service en aura besoin de toute façon.

        Pour installer quand même sans la puce, en connaissance de cause :
        synsec init -sans-elevation`))
		}
		fmt.Println("  Poursuite demandée sans élévation.")
		fmt.Println()
	} else {
		fmt.Println("  Fenêtre    : administrateur")
	}

	// 2. Ce que cette installation obtiendra vraiment.
	//
	//    Deux questions différentes, qu'il ne faut pas confondre : ce que la
	//    machine sait faire, et ce que ce processus-ci peut en tirer. Detect
	//    répond à la première ; sans les droits, la puce reste hors de portée
	//    et c'est le repli qui s'appliquera. Annoncer Detect ici promettrait
	//    une protection que l'installation n'obtiendra pas.
	capable := unseal.Detect(dataDir)
	choisi := capable
	if !isElevated() && capable.Name() != unseal.Fallback(dataDir).Name() {
		choisi = unseal.Fallback(dataDir)
		fmt.Printf("  Hors de portée sans droits : %s\n", providerLabel(capable.Name()))
		fmt.Println()
	}
	protection := choisi.Protection()

	fmt.Printf("  Retenu     : %s\n", providerLabel(choisi.Name()))
	fmt.Println()
	fmt.Printf("  %s\n", wrap(protection.Summary, 64, "  "))
	fmt.Println()

	// 3. Le repli est annoncé pour ce qu'il est, avant, pas après.
	if !protection.ResistsDiskTheft {
		if capable.Name() == choisi.Name() {
			fmt.Println("  ATTENTION : aucune puce TPM utilisable sur cette machine.")
		} else {
			fmt.Println("  ATTENTION : la puce existe mais ne sera pas utilisée.")
		}
		fmt.Println()
		fmt.Printf("  %s\n", wrap(protection.Caveat, 64, "  "))
		fmt.Println()
		// Le conseil du firmware n'a de sens que s'il n'y a pas de puce. Le
		// donner à quelqu'un dont la puce existe et qui manque simplement de
		// droits l'enverrait fouiller un BIOS pour rien.
		if capable.Name() == choisi.Name() {
			fmt.Printf("  %s\n", wrap(noChipAdvice(), 64, "  "))
			fmt.Println()
		}
	}

	fmt.Println(line)
	fmt.Println()
	return nil
}

// noChipAdvice dit quoi faire, plutôt que de laisser le constat en l'air.
//
// Le cas le plus fréquent, et de loin, n'est pas une machine sans puce : c'est
// une machine dont la puce dort dans le firmware, désactivée par défaut.
func noChipAdvice() string {
	return "Beaucoup de cartes ont une puce désactivée en usine : cherche " +
		"fTPM (AMD) ou PTT (Intel) dans le BIOS. Une fois activée, " +
		"« synsec maintenance sceller » déplace la clé sans rien réinstaller."
}
