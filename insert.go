package passr

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"

	"golang.org/x/crypto/openpgp"
)

func Insert(publicKeyringFile, keyName, fdir, name, pass string) error {
	message := pass
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	_, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		return fmt.Errorf("file %s exists", filename)
	}
	keyringFileBuffer, err := os.Open(publicKeyringFile)
	if err != nil {
		return err
	}
	defer func() {
		err := keyringFileBuffer.Close()
		if err != nil {
			logrus.Errorf("Error closing file %s", err)
		}
	}()
	kring, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return err
	}
	err = Encrypt(0, kring, keyName, false, filename, message)
	return err
}
