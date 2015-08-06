package passr

import (
	"fmt"
	"os"
	"path/filepath"
)

func Delete(fdir, name string) error {
	filename := filepath.Join(fdir, fmt.Sprintf("%s.gpg", name))
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", filename)
		}
		return err
	}
	err = os.Remove(filename)
	return err
}
