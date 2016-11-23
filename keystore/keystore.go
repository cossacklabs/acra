package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	. "github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/user"
	"strings"
	"time"
)

const (
	DEFAULT_KEY_DIR_SHORT = "./.acrakeys"
)

func GetDefaultKeyDir() (string, error) {
	return AbsPath(DEFAULT_KEY_DIR_SHORT)
}

func AddNewZone(output_dir string, fs_keystore bool) (string, error) {
	var output, dir string
	if len(output_dir) >= 2 && (output_dir)[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			fmt.Println("Debug: %v\n", ErrorMessage("can't expand '~/'", err))
			return "", err
		}
		dir = usr.HomeDir
		output = strings.Replace(output_dir, "~", dir, 1)
	}
	if output_dir == "." {
		dir, err := os.Getwd()
		if err != nil {
			fmt.Printf("Debug: %v\n", ErrorMessage("can't expand current directory '.'", err))
			return "", err
		}
		output = dir
	}
	var key_store KeyStore
	if fs_keystore {
		key_store = NewFilesystemKeyStore(output)
	}
	id, public_key, err := key_store.GenerateKey()
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage("can't add zone", err))
		return "", err
	}
	public_key_path := fmt.Sprintf("%s/%s", output, GetPublicKeyFilename(id))
	err = ioutil.WriteFile(public_key_path, public_key, 0644)
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage(fmt.Sprintf("can't save public key at path: %s", public_key_path), err))
		return "", err
	}
	response := make(map[string]string)
	response["id"] = string(id)
	response["public_key"] = base64.StdEncoding.EncodeToString(public_key)
	json_output, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("Debug: %v\n", ErrorMessage("can't encode to json", err))
		return "", err
	}
	return string(json_output), nil
}

type KeyStore interface {
	GetKey(id []byte) (*keys.PrivateKey, error)
	HasKey(id []byte) bool
	// return id, public key, error
	GenerateKey() ([]byte, []byte, error)
}

func GetPublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone.pub", string(id))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generate_id() []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, zone.ZONE_ID_LENGTH)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	//return append(zone.ZONE_ID_BEGIN, append(b, ZONE_ID_END...)...)
	return append(zone.ZONE_ID_BEGIN, b...)
}

type OneKeyStore struct {
	key *keys.PrivateKey
}

func NewOneKeyStore(key *keys.PrivateKey) *OneKeyStore {
	return &OneKeyStore{key: key}
}

func (store *OneKeyStore) GenerateKey() ([]byte, []byte, error) {
	return generate_id(), store.key.Value, nil
}

func (store *OneKeyStore) GetKey(id []byte) (*keys.PrivateKey, error) {
	return store.key, nil
}

func (store *OneKeyStore) HasKey([]byte) bool {
	return true
}

type FilesystemKeyStore struct {
	keys      map[string]*keys.PrivateKey
	directory string
}

func NewFilesystemKeyStore(directory string) *FilesystemKeyStore {
	return &FilesystemKeyStore{directory: directory, keys: make(map[string]*keys.PrivateKey)}
}

func (*FilesystemKeyStore) get_key_filename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

func (store *FilesystemKeyStore) GenerateKey() ([]byte, []byte, error) {
	/* save private key in fs, return id and public key*/
	var id []byte
	for {
		// generate until key not exists
		id = generate_id()
		if !store.HasKey(id) {
			break
		}
	}

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	keydir, err := GetDefaultKeyDir()
	if err != nil {
		return []byte{}, []byte{}, err
	}
	err = os.MkdirAll(keydir, 0700)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	err = ioutil.WriteFile(store.get_file_path(fmt.Sprintf("%s_zone", string(id))), keypair.Private.Value, 0600)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	// cache key
	store.keys[store.get_key_filename(id)] = keypair.Private
	return id, keypair.Public.Value, nil
}

func (store *FilesystemKeyStore) get_file_path(filename string) string {
	return fmt.Sprintf("%s%s%s", store.directory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) GetKey(id []byte) (*keys.PrivateKey, error) {
	fname := store.get_key_filename(id)
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return key, nil
	}
	key, err := LoadPrivateKey(store.get_file_path(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = key
	return key, nil
}

func (store *FilesystemKeyStore) HasKey(id []byte) bool {
	// add caching false answers. now if key doesn't exists than always checks on fs
	// it's system call and slow.
	if len(id) == 0 {
		return false
	}
	fname := store.get_key_filename(id)
	_, ok := store.keys[fname]
	if ok {
		return true
	}
	exists, _ := FileExists(store.get_file_path(fname))
	return exists
}
