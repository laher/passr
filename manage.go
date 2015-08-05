package passr

import (
	"fmt"
	"os"
	"strings"
)

func ListPasses(passDir string) {
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
}

func InitRepo(passDir string) {
	err := os.MkdirAll(passDir, 0750)
	if err != nil {
		fmt.Printf("Error creating %s: %s", passDir, err)
		fmt.Println("")
		return
	}

}
