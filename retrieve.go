package passr

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/openpgp"
)

func Retrieve(secretKeyringFile, fdir, name string) (string, error) {
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
			log.Printf("Error closing file %s", err)
		}
	}()
	kring, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	//passphrase := []byte("passphrase")
	fmt.Println("Enter passphrase:")
	passphrase := gopass.GetPasswd()
	p, err := Decrypt(0, kring, false, filename, passphrase)
	return p, err
}
