//go:build windows

package unseal

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Sceller la clé dans la puce, sous Windows.
//
// DPAPI lie le secret à la machine, mais ce qui le déchiffre vit sur le même
// disque : un disque emporté rend les deux moitiés. Une clé de plateforme, au
// contraire, ne sort jamais du TPM - elle n'est pas exportable, par
// construction - donc un disque emporté ne rend que du chiffré.
//
// Ce que ça ne change pas : sur la machine allumée, qui a les droits peut
// toujours demander au TPM de déchiffrer. Une clé sans politique PCR ni valeur
// d'authentification ferme le vol hors ligne, pas l'hôte compromis. C'est le
// prix du démarrage sans personne, et c'est le même arbitrage que sur Linux
// avec systemd-creds.
//
// On passe par CNG plutôt que par les commandes TPM 2.0 brutes : Windows sait
// déjà gérer la puce, la persistance et les droits, et ça évite d'embarquer
// une pile TPM dans le chemin le plus sensible du projet.

var (
	ncrypt   = syscall.NewLazyDLL("ncrypt.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procStringToSecurityDescriptor = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFreeSD                = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procEncrypt             = ncrypt.NewProc("NCryptEncrypt")
	procDecrypt             = ncrypt.NewProc("NCryptDecrypt")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	// platformProvider est le fournisseur CNG adossé au TPM.
	platformProvider = "Microsoft Platform Crypto Provider"

	// tpmKeyName nomme la clé persistée. Stable : c'est par ce nom qu'on la
	// retrouve à chaque démarrage.
	tpmKeyName = "SYNSEC Root Wrapping Key"

	ncryptMachineKeyFlag = 0x00000020
	ncryptSilentFlag     = 0x00000040
	ncryptPadOAEPFlag    = 0x00000004

	// La clé fait 2048 bits : l'OAEP-SHA256 y chiffre jusqu'à 190 octets, et
	// on n'en enveloppe que 32. Toutes les puces TPM 2.0 savent la produire.
	tpmKeyBits = 2048

	// NTE_BAD_KEYSET, rendu quand la clé n'existe pas encore.
	nteBadKeyset = 0x80090016

	// NTE_PERM : les clés machine demandent des droits administrateur. C'est
	// le premier mur sur lequel on tombe, et le code seul ne le dit pas.
	ntePerm = 0x80090010

	// daclSecurityInformation dit à CNG que le descripteur fourni ne porte que
	// la liste d'accès.
	daclSecurityInformation = 0x00000004

	// keyAccess donne la clé au compte du service et aux administrateurs.
	//
	// C'est le point qui décide si le serveur redémarre. « synsec init » est
	// lancé par une personne dans une invite élevée, le service tourne en
	// LocalSystem : sans cette liste posée à la main, on retombe sur le piège
	// que DPAPI a déjà coûté une fois, une clé que seul l'installateur sait
	// rouvrir et un service qui boucle sur son démarrage.
	//
	// SY est LocalSystem, BA le groupe Administrateurs.
	keyAccess = "D:(A;;GA;;;SY)(A;;GA;;;BA)"
)

// machineKey est le jeu de drapeaux de la production : une clé de la machine,
// pas de l'utilisateur, et aucune boîte de dialogue - le service n'a pas de
// bureau pour l'afficher.
const machineKey = ncryptMachineKeyFlag | ncryptSilentFlag

// WindowsTPM protège la clé d'enveloppe avec une clé RSA persistée dans le TPM.
type WindowsTPM struct{}

func (WindowsTPM) Name() string { return "windows-tpm" }

func (WindowsTPM) Protection() Protection {
	return Protection{
		ResistsDiskTheft: true,
		Summary:          "La clé est scellée dans la puce TPM de cette machine : elle n'en sort jamais. Un disque emporté, ou une sauvegarde restaurée ailleurs, est inexploitable.",
		Caveat:           "Sur cette machine en marche, un compte administrateur peut demander au TPM de déchiffrer : c'est ce qui permet au service de démarrer tout seul. Et si la carte mère change, si le TPM est réinitialisé ou si le firmware est remis à zéro, seul le code de récupération imprimé rouvrira le coffre.",
	}
}

// Protect chiffre la clé avec la partie publique de la clé de la puce.
//
// La clé persistée est réutilisée quand elle existe, jamais réécrite : un
// re-scellement doit laisser l'ancien blob ouvrable jusqu'à ce que le nouveau
// soit rangé, sans quoi une panne au mauvais moment fermerait le coffre pour
// de bon.
func (WindowsTPM) Protect(key []byte) ([]byte, error) {
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	handle, err := openOrCreateKey(prov, machineKey)
	if err != nil {
		return nil, err
	}
	defer freeObject(handle)

	return oaep(procEncrypt, handle, key, "chiffrement")
}

// Expose demande au TPM de rouvrir le blob.
func (WindowsTPM) Expose(handle []byte) ([]byte, error) {
	if len(handle) == 0 {
		return nil, ErrNoHandle
	}
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	key, err := openKey(prov, machineKey)
	if err != nil {
		return nil, err
	}
	defer freeObject(key)

	return oaep(procDecrypt, key, handle, "déchiffrement")
}

// windowsTPMAvailable dit si cette machine a une puce utilisable.
//
// Le fournisseur peut être enregistré sans qu'aucune puce ne réponde, ce qui
// est le cas d'une machine dont le TPM dort dans le firmware. On lui demande
// donc son type d'implémentation, et on n'accepte que le matériel : se
// tromper ici ferait promettre à l'installation une garantie inexistante.
func windowsTPMAvailable() bool {
	prov, err := openPlatformProvider()
	if err != nil {
		return false
	}
	defer freeObject(prov)

	const implHardwareFlag = 0x00000001

	name, err := syscall.UTF16PtrFromString("Impl Type")
	if err != nil {
		return false
	}
	var buf [4]byte
	var got uint32
	ret, _, _ := procGetProperty.Call(
		prov,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&got)),
		0,
	)
	if int32(ret) != 0 || got != 4 {
		return false
	}
	return binary.LittleEndian.Uint32(buf[:])&implHardwareFlag != 0
}

func openPlatformProvider() (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(platformProvider)
	if err != nil {
		return 0, fmt.Errorf("unseal: nom du fournisseur : %w", err)
	}
	var prov uintptr
	ret, _, _ := procOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&prov)),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	if int32(ret) != 0 {
		return 0, fmt.Errorf("unseal: NCryptOpenStorageProvider : %s", ncryptError(ret))
	}
	return prov, nil
}

func openKey(prov uintptr, flags uint32) (uintptr, error) {
	name, err := syscall.UTF16PtrFromString(tpmKeyName)
	if err != nil {
		return 0, err
	}
	var key uintptr
	ret, _, _ := procOpenKey.Call(
		prov,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)),
		0, // dwLegacyKeySpec
		uintptr(flags),
	)
	if int32(ret) != 0 {
		return 0, fmt.Errorf("unseal: ouverture de la clé TPM : %s", ncryptError(ret))
	}
	return key, nil
}

// openOrCreateKey rend la clé persistée, en la créant la première fois.
func openOrCreateKey(prov uintptr, flags uint32) (uintptr, error) {
	key, err := openKey(prov, flags)
	if err == nil {
		return key, nil
	}
	if !isMissingKey(err) {
		return 0, err
	}

	name, err := syscall.UTF16PtrFromString(tpmKeyName)
	if err != nil {
		return 0, err
	}
	algo, err := syscall.UTF16PtrFromString("RSA")
	if err != nil {
		return 0, err
	}

	ret, _, _ := procCreatePersistedKey.Call(
		prov,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algo)),
		uintptr(unsafe.Pointer(name)),
		0, // dwLegacyKeySpec
		uintptr(flags&^ncryptSilentFlag),
	)
	if int32(ret) != 0 {
		return 0, fmt.Errorf("unseal: création de la clé TPM : %s", ncryptError(ret))
	}

	if err := setLength(key, tpmKeyBits); err != nil {
		freeObject(key)
		return 0, err
	}
	if ret, _, _ := procFinalizeKey.Call(key, uintptr(ncryptSilentFlag)); int32(ret) != 0 {
		freeObject(key)
		return 0, fmt.Errorf("unseal: NCryptFinalizeKey : %s", ncryptError(ret))
	}

	// Posé après la finalisation, et l'échec est fatal : une clé que le
	// service ne peut pas ouvrir vaut moins qu'une absence de clé, parce
	// qu'elle ne se découvre qu'au redémarrage suivant. Refuser ici fait
	// retomber l'installation sur DPAPI, qui marche.
	if flags&ncryptMachineKeyFlag != 0 {
		if err := grantServiceAccess(key); err != nil {
			freeObject(key)
			return 0, err
		}
	}
	return key, nil
}

// grantServiceAccess écrit la liste d'accès de la clé.
func grantServiceAccess(key uintptr) error {
	sddl, err := syscall.UTF16PtrFromString(keyAccess)
	if err != nil {
		return err
	}

	var sd uintptr
	var size uint32
	ret, _, callErr := procStringToSecurityDescriptor.Call(
		uintptr(unsafe.Pointer(sddl)),
		1, // SDDL_REVISION_1
		uintptr(unsafe.Pointer(&sd)),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return fmt.Errorf("unseal: liste d'accès de la clé TPM : %w", callErr)
	}
	defer procLocalFreeSD.Call(sd) //nolint:errcheck // rien à faire d'un échec de libération

	property, err := syscall.UTF16PtrFromString("Security Descr")
	if err != nil {
		return err
	}
	ret, _, _ = procSetProperty.Call(
		key,
		uintptr(unsafe.Pointer(property)),
		sd,
		uintptr(size),
		uintptr(daclSecurityInformation|ncryptSilentFlag),
	)
	if int32(ret) != 0 {
		return fmt.Errorf("unseal: la clé TPM refuse sa liste d'accès : %s "+
			"(sans elle, le service ne pourrait pas ouvrir le coffre au démarrage)",
			ncryptError(ret))
	}
	return nil
}

func setLength(key uintptr, bits uint32) error {
	property, err := syscall.UTF16PtrFromString("Length")
	if err != nil {
		return err
	}
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], bits)

	ret, _, _ := procSetProperty.Call(
		key,
		uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&value[0])),
		uintptr(len(value)),
		uintptr(ncryptSilentFlag),
	)
	if int32(ret) != 0 {
		return fmt.Errorf("unseal: taille de clé refusée par la puce : %s", ncryptError(ret))
	}
	return nil
}

// oaepPaddingInfo est BCRYPT_OAEP_PADDING_INFO.
type oaepPaddingInfo struct {
	algorithm *uint16
	label     *byte
	labelLen  uint32
}

// oaep appelle NCryptEncrypt ou NCryptDecrypt, qui partagent leur signature.
//
// Deux passes : la première demande la taille du résultat, la seconde le
// remplit. C'est la convention de CNG. Deviner la taille marcherait
// aujourd'hui et casserait le jour où la puce change de gabarit.
func oaep(proc *syscall.LazyProc, key uintptr, in []byte, what string) ([]byte, error) {
	sha, err := syscall.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, err
	}
	padding := oaepPaddingInfo{algorithm: sha}

	var input *byte
	if len(in) > 0 {
		input = &in[0]
	}

	var size uint32
	ret, _, _ := proc.Call(
		key,
		uintptr(unsafe.Pointer(input)),
		uintptr(len(in)),
		uintptr(unsafe.Pointer(&padding)),
		0, // pbOutput
		0, // cbOutput
		uintptr(unsafe.Pointer(&size)),
		uintptr(ncryptPadOAEPFlag|ncryptSilentFlag),
	)
	if int32(ret) != 0 {
		return nil, fmt.Errorf("unseal: %s par le TPM : %s", what, ncryptError(ret))
	}

	out := make([]byte, size)
	ret, _, _ = proc.Call(
		key,
		uintptr(unsafe.Pointer(input)),
		uintptr(len(in)),
		uintptr(unsafe.Pointer(&padding)),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(ncryptPadOAEPFlag|ncryptSilentFlag),
	)
	if int32(ret) != 0 {
		return nil, fmt.Errorf("unseal: %s par le TPM : %s", what, ncryptError(ret))
	}
	return out[:size], nil
}

func freeObject(handle uintptr) {
	if handle != 0 {
		procFreeObject.Call(handle) //nolint:errcheck // rien à faire d'un échec de libération
	}
}

// isMissingKey distingue « la clé n'existe pas encore » de toute autre panne.
// La première se répare en créant la clé ; les autres ne doivent surtout pas
// déclencher une création qui masquerait le vrai problème.
func isMissingKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), ncryptCode(nteBadKeyset))
}

// ncryptError garde le code, qui est ce qu'on retrouve dans une recherche, et
// y ajoute la traduction des deux cas sur lesquels on tombe vraiment.
func ncryptError(ret uintptr) string {
	code := uint32(ret)
	switch code {
	case ntePerm:
		return ncryptCode(code) + " (droits insuffisants : une clé de machine " +
			"demande une invite de commandes administrateur)"
	case nteBadKeyset:
		return ncryptCode(code) + " (aucune clé SYNSEC dans cette puce)"
	}
	return ncryptCode(code)
}

func ncryptCode(code uint32) string { return fmt.Sprintf("0x%08x", code) }
