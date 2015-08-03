package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/howeyc/gopass"
	"github.com/laher/passr"
	"golang.org/x/crypto/openpgp"
)

func insert(publicKeyringFile, fdir, name, pass string) error {
	message := pass
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	keyringFileBuffer, _ := os.Open(publicKeyringFile)
	defer keyringFileBuffer.Close()
	kring, _ := openpgp.ReadKeyRing(keyringFileBuffer)

	//keyRingHex := passr.TestKeys1And2PrivateHex
	//kring, _ := openpgp.ReadKeyRing(passr.ReaderFromHex(keyRingHex))
	err := passr.Encrypt(0, kring, false, filename, message)
	return err
}

func loadKeyring() (openpgp.EntityList, error) {
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return entityList, err
	}
	return entityList, nil
}

func retrieve(secretKeyringFile, fdir, name string) (string, error) {
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	//keyRingHex := passr.TestKeys1And2PrivateHex
	//kring, _ := openpgp.ReadKeyRing(passr.ReaderFromHex(keyRingHex))
	keyringFileBuffer, _ := os.Open(secretKeyringFile)
	defer keyringFileBuffer.Close()
	kring, _ := openpgp.ReadKeyRing(keyringFileBuffer)
	//passphrase := []byte("passphrase")
	fmt.Println("Enter passphrase:")
	passphrase := gopass.GetPasswd()
	p, err := passr.Decrypt(0, kring, false, filename, passphrase)
	return p, err
}

func generate(length int, chars []byte) (string, error) {
	pword := make([]byte, length)
	buf := make([]byte, length+(length/4))
	clen := byte(len(chars))
	maxrb := byte(256 - (256 % len(chars)))
	i := 0
	for {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			if c >= maxrb {
				continue
			}
			pword[i] = chars[c%clen]
			i++
			if i == length {
				return string(pword), nil
			}
		}
	}
	return "", fmt.Errorf("Random data not found")
}
