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

//	pass := gopass.GetPasswd() // Silent, for *'s use gopass.GetPasswdMasked()
// Do something with pass
func main() {
	app := cli.NewApp()
	app.Name = "passr"
	app.Usage = "password recollector"
	u, err := user.Current()
	if err != nil {
		logrus.Errorf("Error getting current user: %s", err)
		return
	}
	hd := u.HomeDir
	config := passr.DefaultConfig()
	passDir := filepath.Join(u.HomeDir, config.PassDir)
	publicKeyringFile := filepath.Join(hd, config.PubKeyring)
	secretKeyringFile := filepath.Join(hd, config.PrivKeyring)
	keyName := config.KeyId
	app.Commands = []cli.Command{
		{
			Name:    "list",
			Aliases: []string{"ls", "l"},
			Usage:   "list passwords",
			Action: func(c *cli.Context) {
				err := passr.ListPasses(passDir)
				if err != nil {
					logrus.Errorf("Error listing passes: %s", err)
					return
				}
			},
		},
		{
			Name:    "init",
			Aliases: []string{"prep"},
			Usage:   "Prepare a repo",
			Action: func(c *cli.Context) {
				err := passr.InitRepo(passDir)
				if err != nil {
					logrus.Errorf("Error preparing repo: %s", err)
					return
				}
			},
		},
		{
			Name:    "generate",
			Aliases: []string{"g", "gen"},
			Usage:   "generate a password",
			Action: func(c *cli.Context) {
				p, err := passr.GenerateDef()
				if err != nil {
					logrus.Errorf("Error generating password: %s", err)
					return
				}
				err = passr.Insert(publicKeyringFile, keyName, passDir, c.Args().First(), p)
				if err != nil {
					logrus.Errorf("Error inserting password: %s", err)
					return
				}
				logrus.Infof("Generated password:")
				fmt.Print(p)
			},
		},
		{
			Name:    "insert",
			Aliases: []string{"i", "ins", "put"},
			Usage:   "insert a password",
			Action: func(c *cli.Context) {
				if len(c.Args()) < 2 {
					logrus.Errorf("Password required")
					return
				}
				err := passr.Insert(publicKeyringFile, keyName, passDir, c.Args().First(), c.Args()[1])
				if err != nil {
					logrus.Errorf("Error inserting password: %s", err)
					return
				}
				logrus.Infof("Inserted password: %s", c.Args().First())
			},
		},
		{
			Name:    "read",
			Aliases: []string{"r", "retrieve", "show"},
			Usage:   "retrieve a password",
			Action: func(c *cli.Context) {
				p, err := passr.Retrieve(secretKeyringFile, keyName, passDir, c.Args().First())
				if err != nil {
					logrus.Errorf("Error retrieving password: %s", err)
					return
				}
				fmt.Print(p)
			},
		},
		{
			Name:    "delete",
			Aliases: []string{"del", "d"},
			Usage:   "delete a password",
			Action: func(c *cli.Context) {
				err := passr.Delete(passDir, c.Args().First())
				if err != nil {
					logrus.Errorf("Error retrieving key: %s", err)
					return
				}
				logrus.Infof("Deleted password: %s", c.Args().First())
			},
		}}
	err = app.Run(os.Args)
	if err != nil {
		log.Printf("Error: %s", err)
		os.Exit(1)
	}
}
