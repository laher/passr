package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/laher/passr"
)

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
			Aliases: []string{"ls", "l"},
			Usage:   "list passwords",
			Action: func(c *cli.Context) {
				passr.ListPasses(passDir)
			},
		},
		{
			Name:    "init",
			Aliases: []string{"prep"},
			Usage:   "Prepare a repo",
			Action: func(c *cli.Context) {
				passr.InitRepo(passDir)
			},
		},
		{
			Name:    "generate",
			Aliases: []string{"g", "gen"},
			Usage:   "generate a password",
			Action: func(c *cli.Context) {
				p, err := passr.GenerateDef()
				if err != nil {
					logrus.Errorf("Error generating %s", err)
					return
				}
				publicKeyringFile := filepath.Join(hd, publicKeyring)
				err = passr.Insert(publicKeyringFile, keyName, passDir, c.Args().First(), p)
				if err != nil {
					logrus.Errorf("Error inserting %s", err)
					return
				}
				fmt.Printf("Generated %s", p)
				fmt.Println("")
			},
		},
		{
			Name:    "insert",
			Aliases: []string{"i", "ins", "put"},
			Usage:   "insert a password",
			Action: func(c *cli.Context) {
				publicKeyringFile := filepath.Join(hd, publicKeyring)
				err := passr.Insert(publicKeyringFile, keyName, passDir, c.Args().First(), c.Args()[1])
				if err != nil {
					logrus.Errorf("Error inserting %s", err)
					return
				}
				fmt.Printf("Inserted %s", c.Args().First())
				fmt.Println("")
			},
		},
		{
			Name:    "read",
			Aliases: []string{"r", "retrieve", "show"},
			Usage:   "retrieve a password",
			Action: func(c *cli.Context) {
				secretKeyringFile := filepath.Join(hd, secretKeyring)
				p, err := passr.Retrieve(secretKeyringFile, keyName, passDir, c.Args().First())
				if err != nil {
					logrus.Errorf("Error retrieving %s", err)
					return
				}
				fmt.Print(p)
			},
		}}
	err = app.Run(os.Args)
	if err != nil {
		log.Printf("Error: %s", err)
		os.Exit(1)
	}
}

const secretKeyring = ".gnupg/secring.gpg"
const publicKeyring = ".gnupg/pubring.gpg"
const keyName = "78C56BB6"
