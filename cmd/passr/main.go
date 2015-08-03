package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)
import (
	"github.com/codegangsta/cli"
	"github.com/laher/passr"
)

const Folder = ".passr"

//	fmt.Printf("Password: ")
//	pass := gopass.GetPasswd() // Silent, for *'s use gopass.GetPasswdMasked()
// Do something with pass
func main() {
	app := cli.NewApp()
	app.Name = "passr"
	app.Usage = "password recollector"
	u, err := user.Current()
	if err != nil {
		fmt.Println("Error getting current user: %s", err)
	}
	f := filepath.Join(u.HomeDir, Folder)
	fmt.Printf("dir: %s", f)
	fmt.Println("")
	app.Commands = []cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "list passwords",
			Action: func(c *cli.Context) {
				d, err := os.Open(f)
				if err != nil {
					fmt.Printf("Error opening %s: %s", f, err)
					fmt.Println("")
				}
				names, err := d.Readdirnames(100)
				if err != nil {
					fmt.Printf("Error reading %s: %s", f, err)
					fmt.Println("")
				}
				for _, name := range names {
					fmt.Printf(" %s", name)
					fmt.Println("")
				}
			},
		},
		{
			Name:    "init",
			Aliases: []string{"i"},
			Usage:   "create a repo",
			Action: func(c *cli.Context) {

				err = os.MkdirAll(f, 0750)
				if err != nil {
					fmt.Printf("Error creating %s: %s", Folder, err)
					fmt.Println("")
				}
			},
		},
		{
			Name:    "generate",
			Aliases: []string{"g", "gen"},
			Usage:   "generate a password",
			Action: func(c *cli.Context) {
				p, err := generate(15, StdChars)
				if err != nil {
					fmt.Printf("Error generating %s", err)
					fmt.Println("")
				}
				fmt.Printf("Generated %s", p)
				fmt.Println("")
			},
		},
		{
			Name:    "insert",
			Aliases: []string{"ins"},
			Usage:   "insert a password",
			Action: func(c *cli.Context) {
				err := insert(c.Args().First(), c.Args()[1])
				if err != nil {
					fmt.Printf("Error inserting %s", err)
					fmt.Println("")
				}
				fmt.Printf("Inserted %s", c.Args().First())
				fmt.Println("")
			},
		},
		{
			Name:    "get",
			Aliases: []string{"g"},
			Usage:   "retrieve a password",
			Action: func(c *cli.Context) {
				p, err := retrieve(c.Args().First())
				if err != nil {
					fmt.Printf("Error retrieving %s", err)
					fmt.Println("")
				}
				fmt.Printf("Retrieved %s:", c.Args().First())
				fmt.Println("")
				fmt.Printf("%s", p)
				fmt.Println("")
			},
		}}
	app.Run(os.Args)
}

func insert(name, pass string) error {
	message := pass
	filename := fmt.Sprintf("%s.gpg", name)
	keyRingHex := passr.TestKeys1And2PrivateHex
	kring, _ := openpgp.ReadKeyRing(passr.ReaderFromHex(keyRingHex))
	passphrase := []byte("passphrase")
	err := passr.Encrypt(0, kring, false, filename, message, passphrase)
	return err
}

func retrieve(name string) (string, error) {
	filename := fmt.Sprintf("%s.gpg", name)
	keyRingHex := passr.TestKeys1And2PrivateHex
	kring, _ := openpgp.ReadKeyRing(passr.ReaderFromHex(keyRingHex))
	passphrase := []byte("passphrase")
	p, err := passr.Decrypt(0, kring, false, filename, passphrase)
	return p, err
}

var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~")

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
