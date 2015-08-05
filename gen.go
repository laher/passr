package passr

import (
	"crypto/rand"
	"fmt"
	"io"
)

var All = Caps + Lowers + Numbers + Punc
var Punc = "!@#$%^&*()-_=+,.?/:;{}[]`~"
var Caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
var Lowers = "abcdefghijklmnopqrstuvwxyz"
var Numbers = "0123456789"

func GenerateDef() (string, error) {
	return Generate(30, []byte(All))
}

func Generate(length int, chars []byte) (string, error) {
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
