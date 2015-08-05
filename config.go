package passr

type Config struct {
	PassDir     string
	PubKeyring  string
	PrivKeyring string
	KeyId       string
}

const PassrDir = ".passr"
const secretKeyring = ".gnupg/secring.gpg"
const publicKeyring = ".gnupg/pubring.gpg"
const keyName = "78C56BB6"

func DefaultConfig() *Config {
	return &Config{
		PassDir:     PassrDir,
		PubKeyring:  publicKeyring,
		PrivKeyring: secretKeyring,
		KeyId:       keyName,
	}
}
