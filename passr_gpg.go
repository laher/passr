package passr

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"

	"github.com/Sirupsen/logrus"
)

func ReaderFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("ReaderFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}

func enc(i int, keyRingHex string, isSigned bool, filename string, message string, passphraseS string) error {
	kring, _ := openpgp.ReadKeyRing(ReaderFromHex(keyRingHex))
	passphrase := []byte(passphraseS)
	return Encrypt(i, kring, isSigned, filename, message, passphrase)
}

func Encrypt(index int, kring openpgp.EntityList, isSigned bool, filename string, message string, passphrase []byte) error {

	for _, entity := range kring {
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			err := entity.PrivateKey.Decrypt(passphrase)
			if err != nil {
				logrus.Errorf("#%d: failed to decrypt key", index)
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				err := subkey.PrivateKey.Decrypt(passphrase)
				if err != nil {
					logrus.Errorf("#%d: failed to decrypt subkey", index)
				}
			}
		}
	}

	var signed *openpgp.Entity
	if isSigned {
		signed = kring[0]
	}

	//buf := new(bytes.Buffer)
	f, err := os.Create(filename)
	if err != nil {
		logrus.Errorf("#%d: error in Create: %s", index, err)
		return err
	}
	w, err := openpgp.Encrypt(f, kring[:1], signed, nil /* no hints */, nil)
	if err != nil {
		logrus.Errorf("#%d: error in Encrypt: %s", index, err)
		return err
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		logrus.Errorf("#%d: error writing plaintext: %s", index, err)
		return err
	}
	err = w.Close()
	if err != nil {
		logrus.Errorf("#%d: error closing WriteCloser: %s", index, err)
		return err
	}
	err = f.Close()
	if err != nil {
		logrus.Errorf("#%d: error closing file: %s", index, err)
		return err
	}
	return nil
}

func Decrypt(index int, kring openpgp.EntityList, isSigned bool, filename string, passphrase []byte) (string, error) {
	f2, err := os.Open(filename)
	if err != nil {
		logrus.Errorf("#%d: error in Create: %s", index, err)
		return "", err
	}

	md, err := openpgp.ReadMessage(f2, kring, nil /* no prompt */, nil)
	if err != nil {
		logrus.Errorf("#%d: error reading message: %s", index, err)
		return "", err
	}

	/*
		testTime, _ := time.Parse("2006-01-02", "2013-07-01")
			if isSigned {
				signKey, _ := kring[0].signingKey(testTime)
				expectedKeyId := signKey.PublicKey.KeyId
				if md.SignedByKeyId != expectedKeyId {
					logrus.Errorf("#%d: message signed by wrong key id, got: %d, want: %d", i, *md.SignedBy, expectedKeyId)
				}
				if md.SignedBy == nil {
					logrus.Errorf("#%d: failed to find the signing Entity", i)
				}
			}
	*/
	plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		logrus.Errorf("#%d: error reading encrypted contents: %s", index, err)
		return "", err
	}
	/*
			encryptKey, _ := kring[0].encryptionKey(testTime)
			expectedKeyId := encryptKey.PublicKey.KeyId
			if len(md.EncryptedToKeyIds) != 1 || md.EncryptedToKeyIds[0] != expectedKeyId {
				logrus.Errorf("#%d: expected message to be encrypted to %v, but got %#v", i, expectedKeyId, md.EncryptedToKeyIds)
			}

		if string(plaintext) != message {
			logrus.Errorf("#%d: got: %s, want: %s", index, string(plaintext), message)
		}
	*/

	if isSigned {
		if md.SignatureError != nil {
			logrus.Errorf("#%d: signature error: %s", index, md.SignatureError)
		}
		if md.Signature == nil {
			logrus.Error("signature missing")
		}
	}

	return string(plaintext), nil
}
