package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)
import "github.com/codegangsta/cli"

const PassrDir = ".passr"

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
	passDir := filepath.Join(u.HomeDir, PassrDir)
	hd := u.HomeDir
	//fmt.Printf("dir: %s", f)
	//fmt.Println("")
	app.Commands = []cli.Command{
		{
			Name:    "list",
			Aliases: []string{"ls"},
			Usage:   "list passwords",
			Action: func(c *cli.Context) {
				d, err := os.Open(passDir)
				if err != nil {
					fmt.Printf("Error opening %s: %s", passDir, err)
					fmt.Println("")
					return
				}
				names, err := d.Readdirnames(100)
				if err != nil {
					fmt.Printf("Error reading %s: %s", passDir, err)
					fmt.Println("")
					return
				}
				for _, name := range names {
					if strings.HasSuffix(name, ".gpg") {
						fmt.Printf(" %s", strings.Replace(name, ".gpg", "", 1))
						fmt.Println("")
					}
				}
			},
		},
		{
			Name:    "init",
			Aliases: []string{"i"},
			Usage:   "create a repo",
			Action: func(c *cli.Context) {

				err = os.MkdirAll(passDir, 0750)
				if err != nil {
					fmt.Printf("Error creating %s: %s", PassrDir, err)
					fmt.Println("")
					return
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
					return
				}
				fmt.Printf("Generated %s", p)
				fmt.Println("")
			},
		},
		{
			Name:    "insert",
			Aliases: []string{"ins", "put"},
			Usage:   "insert a password",
			Action: func(c *cli.Context) {
				publicKeyringFile := filepath.Join(hd, publicKeyring)
				err := insert(publicKeyringFile, passDir, c.Args().First(), c.Args()[1])
				if err != nil {
					fmt.Printf("Error inserting %s", err)
					fmt.Println("")
					return
				}
				fmt.Printf("Inserted %s", c.Args().First())
				fmt.Println("")
			},
		},
		{
			Name:    "get",
			Aliases: []string{"g", "retrieve", "show"},
			Usage:   "retrieve a password",
			Action: func(c *cli.Context) {
				secretKeyringFile := filepath.Join(hd, secretKeyring)
				p, err := retrieve(secretKeyringFile, passDir, c.Args().First())
				if err != nil {
					fmt.Printf("Error retrieving %s", err)
					fmt.Println("")
					return
				}
				fmt.Printf("Retrieved %s:", c.Args().First())
				fmt.Println("")
				fmt.Printf("%s", p)
				fmt.Println("")
			},
		}}
	app.Run(os.Args)
}

const secretKeyring = ".gnupg/secring.gpg"
const publicKeyring = ".gnupg/pubring.gpg"

var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~")
