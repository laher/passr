package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"

	"github.com/Sirupsen/logrus"
)

var filename = "file.gpg"

const message = "testing123"

var testEncryptionTests = []struct {
	keyRingHex string
	isSigned   bool
}{
	{
		testKeys1And2PrivateHex,
		false,
	},
	{
		testKeys1And2PrivateHex,
		true,
	},
	{
		dsaElGamalTestKeysHex,
		false,
	},
	{
		dsaElGamalTestKeysHex,
		true,
	},
}

func main() {
	for i, test := range testEncryptionTests {
		if i == 0 {
			enc(i, test.keyRingHex, test.isSigned)
		}
	}
}
func readerFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("readerFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}
func enc(i int, keyRingHex string, isSigned bool) error {
	kring, _ := openpgp.ReadKeyRing(readerFromHex(keyRingHex))

	passphrase := []byte("passphrase")
	for _, entity := range kring {
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			err := entity.PrivateKey.Decrypt(passphrase)
			if err != nil {
				logrus.Errorf("#%d: failed to decrypt key", i)
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
				err := subkey.PrivateKey.Decrypt(passphrase)
				if err != nil {
					logrus.Errorf("#%d: failed to decrypt subkey", i)
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
		logrus.Errorf("#%d: error in Create: %s", i, err)
		return err
	}
	w, err := openpgp.Encrypt(f, kring[:1], signed, nil /* no hints */, nil)
	if err != nil {
		logrus.Errorf("#%d: error in Encrypt: %s", i, err)
		return err
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		logrus.Errorf("#%d: error writing plaintext: %s", i, err)
		return err
	}
	err = w.Close()
	if err != nil {
		logrus.Errorf("#%d: error closing WriteCloser: %s", i, err)
		return err
	}
	err = f.Close()
	if err != nil {
		logrus.Errorf("#%d: error closing file: %s", i, err)
		return err
	}
	f2, err := os.Open(filename)
	if err != nil {
		logrus.Errorf("#%d: error in Create: %s", i, err)
		return err
	}

	md, err := openpgp.ReadMessage(f2, kring, nil /* no prompt */, nil)
	if err != nil {
		logrus.Errorf("#%d: error reading message: %s", i, err)
		return err
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
		logrus.Errorf("#%d: error reading encrypted contents: %s", i, err)
		return err
	}

	/*
		encryptKey, _ := kring[0].encryptionKey(testTime)
		expectedKeyId := encryptKey.PublicKey.KeyId
		if len(md.EncryptedToKeyIds) != 1 || md.EncryptedToKeyIds[0] != expectedKeyId {
			logrus.Errorf("#%d: expected message to be encrypted to %v, but got %#v", i, expectedKeyId, md.EncryptedToKeyIds)
		}
	*/

	if string(plaintext) != message {
		logrus.Errorf("#%d: got: %s, want: %s", i, string(plaintext), message)
	}

	if isSigned {
		if md.SignatureError != nil {
			logrus.Errorf("#%d: signature error: %s", i, md.SignatureError)
		}
		if md.Signature == nil {
			logrus.Error("signature missing")
		}
	}

	return nil
}
