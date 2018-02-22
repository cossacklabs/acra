package firewall

import (
	"io/ioutil"
	"path"
	"os"
)

const (
	BLACKLIST_PATH = "blacklist"
	WHITELIST_PATH = "whitelist"
)

//Filesystem-based implementation of AcraFirewall interface (firewall_interface.go)
type FilesystemAcraFirewall struct {

	whitelistPath string
	blacklistPath string
}



func NewFilesystemAcraFirewall(directoryPath string) (*FilesystemAcraFirewall, error) {

	//Create filesystem storage
	var workingDir string
	workingDir, err := os.Getwd()
	if err != nil{
		return nil, err
	}

	whitelistPath := path.Join(workingDir, WHITELIST_PATH)
	blacklistPath := path.Join(workingDir, BLACKLIST_PATH)

	//Create whitelist file if not exist
	if _, err := os.Stat(whitelistPath); os.IsNotExist(err) {
		err = ioutil.WriteFile(whitelistPath, []byte(""), 0644)
		if err != nil{
			return nil, err
		}
	}

	//Create blacklist file if not exist
	if _, err := os.Stat(blacklistPath); os.IsNotExist(err) {
		err = ioutil.WriteFile(blacklistPath, []byte(""), 0644)
		if err != nil{
			return nil, err
		}
	}

	return &FilesystemAcraFirewall{whitelistPath: whitelistPath, blacklistPath: blacklistPath}, nil
}

func (firewall * FilesystemAcraFirewall) ProcessQuery(sqlQuery string) error {

	//ValidateUserInput(sqlQuery)

	handle(firewall, sqlQuery, specificQueryHandler);

	return nil
}

func handle(firewall * FilesystemAcraFirewall, sqlQuery string, specificQueryHandler storageHandlingCallback){

	specificQueryHandler(sqlQuery, firewall.blacklistPath, firewall.whitelistPath)

}

//Not implemented yet
func (firewall*FilesystemAcraFirewall) GetStoredQueries() []string {

	return nil
}



