package validation

import (
	"errors"
)

func isAnnexedWitness(witness []string) bool {
	if len(witness) < 2 {
		return false
	}
	lastElement := witness[len(witness)-1]
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
