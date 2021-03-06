package passr

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
)

func Retrieve(secretKeyringFile, keyName, fdir, name string) (string, error) {
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	//keyRingHex := passr.TestKeys1And2PrivateHex
	//kring, _ := openpgp.ReadKeyRing(passr.ReaderFromHex(keyRingHex))
	keyringFileBuffer, err := os.Open(secretKeyringFile)
	if err != nil {
		return "", err
	}
	defer func() {
		err := keyringFileBuffer.Close()
		if err != nil {
			logrus.Errorf("Error closing file %s", err)
		}
	}()
	kring, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	//passphrase := []byte("passphrase")
	logrus.Infof("Enter passphrase:")
	passphrase := gopass.GetPasswd()
	p, err := Decrypt(0, kring, keyName, false, filename, passphrase)
	return p, err
}
