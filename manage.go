package passr

import (
	"fmt"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
)

func ListPasses(passDir string) error {
	d, err := os.Open(passDir)
	if err != nil {
		logrus.Errorf("Error opening %s: %s", passDir, err)
		return err
	}
	names, err := d.Readdirnames(100)
	if err != nil {
		logrus.Errorf("Error reading %s: %s", passDir, err)
		return err
	}
	logrus.Infof("Listing passes:")
	for _, name := range names {
		if strings.HasSuffix(name, ".gpg") {
			fmt.Printf("%s\n", strings.Replace(name, ".gpg", "", 1))
		}
	}
	return nil
}

func InitRepo(passDir string) error {
	err := os.MkdirAll(passDir, 0750)
	if err != nil {
		logrus.Errorf("Error creating %s: %s", passDir, err)
		return err
	}
	return nil
}
