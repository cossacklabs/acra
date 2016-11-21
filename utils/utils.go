package utils

import (
	"encoding/binary"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
	"io/ioutil"

	"os"
	"os/user"
	"strings"
)

func WriteFull(data []byte, wr io.Writer) (int, error) {
	/* write data to io.Writer. if wr.Write will return n <= len(data) will
	sent the rest of data until error or total sent byte count == len(data)
	*/
	slice_copy := data[:]
	total_sent := 0
	for {
		n, err := wr.Write(slice_copy)
		if err != nil {
			return 0, err
		}
		total_sent += n
		if total_sent == len(data) {
			return total_sent, nil
		}
		slice_copy = slice_copy[total_sent:]
	}
}

func SendData(data []byte, conn io.Writer) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(data)))
	_, err := WriteFull(buf[:], conn)
	if err != nil {
		return err
	}
	_, err = WriteFull(data, conn)
	if err != nil {
		return err
	}
	return nil
}

func ReadData(reader io.Reader) ([]byte, error) {
	var length [4]byte
	_, err := io.ReadFull(reader, length[:])
	if err != nil {
		return nil, err
	}
	data_size := int(binary.LittleEndian.Uint32(length[:]))
	buf := make([]byte, data_size)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func AbsPath(path string) (string, error) {
	if path[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			return path, err
		}
		dir := usr.HomeDir
		path = strings.Replace(path, "~", dir, 1)
		return path, nil
	} else if path[:2] == "./" {
		usr, err := user.Current()
		if err != nil {
			return path, err
		}
		dir := usr.HomeDir
		path = strings.Replace(path, ".", dir, 1)
		return path, nil
	}
	return path, nil
}

func ReadFile(path string) ([]byte, error) {
	abs_path, err := AbsPath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(abs_path)
	if err != nil {
		return nil, err
	}
	key, err := ioutil.ReadAll(file)
	return key, nil
}

func LoadPublicKey(path string) (*keys.PublicKey, error) {
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}

func LoadPrivateKey(path string) (*keys.PrivateKey, error) {
	key, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: key}, nil
}

func FillSlice(value byte, data []byte) {
	for i, _ := range data {
		data[i] = value
	}
}

func FileExists(path string) (bool, error) {
	abs_path, err := AbsPath(path)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(abs_path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}
