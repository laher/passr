package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)
import "github.com/codegangsta/cli"

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
					fmt.Println("Error creating %s: %s", Folder, err)
				}
			},
		}}
	app.Run(os.Args)
}
