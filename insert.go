package passr

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

func Insert(publicKeyringFile, fdir, name, pass string) error {
	message := pass
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	keyringFileBuffer, err := os.Open(publicKeyringFile)
	if err != nil {
		return err
	}
	defer func() {
		err := keyringFileBuffer.Close()
		if err != nil {
			log.Printf("Error closing file %s", err)
		}
	}()
	kring, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return err
	}
	err = Encrypt(0, kring, false, filename, message)
	return err
}
