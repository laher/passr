package passr

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"

	"camlistore.org/pkg/misc/gpgagent"
	"camlistore.org/pkg/misc/pinentry"
	"github.com/Sirupsen/logrus"
)

//from camlistore jsonsign
func decryptEntity(e *openpgp.Entity, key string) error {
	// TODO: syscall.Mlock a region and keep pass phrase in it.
	pubk := &e.PrivateKey.PublicKey
	desc := fmt.Sprintf("Need to unlock GPG key %s to use it for signing.",
		pubk.KeyIdShortString())

	conn, err := gpgagent.NewConn()
	switch err {
	case gpgagent.ErrNoAgent:
		logrus.Errorf("Note: gpg-agent not found; resorting to on-demand password entry.")
	case nil:
		defer conn.Close()
		req := &gpgagent.PassphraseRequest{
			CacheKey: "passr:decrypt:" + pubk.KeyIdShortString(),
			Prompt:   "Passphrase",
			Desc:     desc,
		}
		for tries := 0; tries < 2; tries++ {
			pass, err := conn.GetPassphrase(req)
			if err == nil {
				err = e.PrivateKey.Decrypt([]byte(pass))
				if err == nil {
					return nil
				}
				req.Error = "Passphrase failed to decrypt: " + err.Error()
				conn.RemoveFromCache(req.CacheKey)
				continue
			}
			if err == gpgagent.ErrCancel {
				return errors.New("failed to decrypt key; action canceled")
			}
			logrus.Errorf("gpgagent: %v", err)
		}
	default:
		logrus.Errorf("gpgagent: %v", err)
	}

	pinReq := &pinentry.Request{Desc: desc, Prompt: "Passphrase"}
	for tries := 0; tries < 2; tries++ {
		pass, err := pinReq.GetPIN()
		if err == nil {
			err = e.PrivateKey.Decrypt([]byte(pass))
			if err == nil {
				return nil
			}
			pinReq.Error = "Passphrase failed to decrypt: " + err.Error()
			continue
		}
		if err == pinentry.ErrCancel {
			return errors.New("failed to decrypt key; action canceled")
		}
		logrus.Errorf("pinentry: %v", err)
	}
	return fmt.Errorf("failed to decrypt key %q", pubk.KeyIdShortString())
}

func loadKeyringFile(kr string) (openpgp.EntityList, error) {
	keyringFileBuffer, err := os.Open(kr)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := keyringFileBuffer.Close()
		if err != nil {
			logrus.Errorf("Error closing file %s", err)
		}
	}()
	return loadKeyring(keyringFileBuffer)
}

func loadKeyring(keyringReader io.Reader) (openpgp.EntityList, error) {
	entityList, err := openpgp.ReadKeyRing(keyringReader)
	if err != nil {
		return entityList, err
	}
	return entityList, nil
}

func ReaderFromHex(s string) io.Reader {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic("ReaderFromHex: bad input")
	}
	return bytes.NewBuffer(data)
}

func enc(i int, keyRingHex string, keyName string, isSigned bool, filename string, message string, passphraseS string) error {
	kring, err := openpgp.ReadKeyRing(ReaderFromHex(keyRingHex))
	if err != nil {
		return err
	}
	return Encrypt(i, kring, keyName, isSigned, filename, message)
}

func DecryptPw(kring openpgp.EntityList, keyName string, passphrase []byte) error {
	for _, entity := range kring {
		pubk := entity.PrivateKey.PublicKey
		logrus.Infof("Key: %s", pubk.KeyIdShortString())
		if pubk.KeyIdShortString() == keyName {
			if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
				err := entity.PrivateKey.Decrypt(passphrase)
				if err != nil {
					logrus.Errorf("failed to decrypt key")
					return err
				}
			}
			for _, subkey := range entity.Subkeys {

				subpubk := subkey.PrivateKey.PublicKey
				logrus.Infof("SubKey: %s", subpubk.KeyIdShortString())
				//	if subpubk.KeyIdShortString() == keyName {
				if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
					err := subkey.PrivateKey.Decrypt(passphrase)
					if err != nil {
						logrus.Errorf("failed to decrypt subkey")
						return err
					}
				}
				//	}
			}
		}
	}
	return nil
}

func Encrypt(index int, kring openpgp.EntityList, keyName string, isSigned bool, filename string, message string) error {

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
	whichKey := openpgp.EntityList{}
	if keyName == "" {
		whichKey = kring[:1]
	} else {
		for _, entity := range kring {
			if entity.PrivateKey != nil {
				pubk := entity.PrivateKey.PublicKey
				logrus.Infof("Key: %s", pubk.KeyIdShortString())
				if pubk.KeyIdShortString() == keyName {
					whichKey = append(whichKey, entity)
				}
			} else {
				if entity.PrimaryKey.KeyIdShortString() == keyName {
					whichKey = append(whichKey, entity)
				}
			}
		}
	}
	w, err := openpgp.Encrypt(f, whichKey, signed, nil /* no hints */, nil)
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

/*
func Dec(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	logrus.Infof("keys: %+v, symm: %v", keys, symmetric)
	return []byte("passphrase"), nil
}
*/

func Decrypt(index int, kring openpgp.EntityList, keyName string, isSigned bool, filename string, passphrase []byte) (string, error) {

	err := DecryptPw(kring, keyName, passphrase)
	if err != nil {
		return "", err
	}

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
