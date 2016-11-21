package utils_test

import (
	"github.com/cossacklabs/acra/utils"
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {
	test_path := "/tmp/testfilepath"
	exists, err := utils.FileExists(test_path)
	if exists || err != nil {
		t.Fatalf("File exists or returned any error. err = %v\n", err)
	}
	_, err = os.Create(test_path)
	defer os.Remove(test_path)
	if err != nil {
		t.Fatalf("Can't create test temporary file %v. err - %v\n", test_path, err)
	}
	exists, err = utils.FileExists(test_path)
	if !exists || err != nil {
		t.Fatalf("File not exists or returned any error. err = %v\n", err)
	}
}
