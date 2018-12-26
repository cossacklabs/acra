package common

import (
	"io/ioutil"
	"os"
)

// FileLogStorage is a file-based implementation of LogStorage interface
type FileLogStorage struct {
	filePath       string
	file           *os.File
	openedToAppend bool
}

// NewFileLogStorage is a constructor for FileLogStorage
func NewFileLogStorage(filePath string) (*FileLogStorage, error) {
	openedFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	fileLogStorage := &FileLogStorage{}
	fileLogStorage.file = openedFile
	fileLogStorage.filePath = filePath
	fileLogStorage.openedToAppend = true
	return fileLogStorage, nil
}

// ReadAll returns stored queries in raw form from internal file
func (storage *FileLogStorage) ReadAll() ([]byte, error) {
	return ioutil.ReadFile(storage.filePath)
}

// WriteAll writes raw queries that need to be stored to internal file
func (storage *FileLogStorage) WriteAll(p []byte) error {
	if storage.openedToAppend {
		openedFile, err := os.OpenFile(storage.filePath, os.O_TRUNC|os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		storage.file = openedFile
		storage.openedToAppend = false
	}
	_, err := storage.file.Write(p)
	if err != nil {
		return err
	}
	return nil
}

// Append appends raw queries to the end of internal file
func (storage *FileLogStorage) Append(p []byte) error {
	if !storage.openedToAppend {
		openedFile, err := os.OpenFile(storage.filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		storage.file = openedFile
		storage.openedToAppend = true
	}
	_, err := storage.file.Write(p)
	if err != nil {
		return err
	}
	return nil
}

// Close simply closes internal file
func (storage *FileLogStorage) Close() error {
	return storage.file.Close()
}
