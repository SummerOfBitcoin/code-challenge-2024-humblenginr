package validation

import (
	"encoding/hex"
	"errors"
)

func isAnnexedWitness(witness []string) bool {
	if len(witness) < 2 {
		return false
	}
	lastElementString := witness[len(witness)-1]
    lastElement,_ := hex.DecodeString(lastElementString)
    // taken from BIP341 https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
	return len(lastElement) > 0 && lastElement[0] == 0x50

}

func ExtractAnnex(witness []string) (string, error) {
	if !isAnnexedWitness(witness) {
        return "", errors.New("Annex not found in the witness")
	}
	lastElement := witness[len(witness)-1]
	return lastElement, nil
}

func RemoveAnnexFromWitness(witness []string)([]string, error) {
    if !isAnnexedWitness(witness) {
        return witness, errors.New("Annex not found in the witness")
	}
    return witness[:len(witness)-2], nil
}

