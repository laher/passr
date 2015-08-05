package passr

import "testing"

var filename = "file.gpg"

const message = "testing123"

var testEncryptionTests = []struct {
	keyRingHex string
	isSigned   bool
}{
	{
		TestKeys1And2PrivateHex,
		false,
	},
	{
		TestKeys1And2PrivateHex,
		true,
	},
	{
		dsaElGamalTestKeysHex,
		false,
	},
	/*
		{
			dsaElGamalTestKeysHex,
			true,
		},
	*/
}

func Test1(t *testing.T) {
	for i, test := range testEncryptionTests {
		err := enc(i, test.keyRingHex, test.isSigned, filename, message, "passphrase")
		if err != nil {
			t.Errorf("Error: %s", err)
		}
	}
}
