package main

import "testing"

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

func Test1(t *testing.T) {
	for i, test := range testEncryptionTests {
		if i == 0 {
			enc(i, test.keyRingHex, test.isSigned, filename, message, "passphrase")
		}
	}
}