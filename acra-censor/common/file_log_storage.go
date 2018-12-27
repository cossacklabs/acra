package common

import (
	"io/ioutil"
	"os"
	"sync"
)

// FileLogStorage is a file-based implementation of LogStorage interface
type FileLogStorage struct {
	file  *os.File
	mutex *sync.Mutex
}

// NewFileLogStorage is a constructor for FileLogStorage
func NewFileLogStorage(filePath string) (*FileLogStorage, error) {
	openedFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return &FileLogStorage{file:openedFile, mutex:&sync.Mutex{}}, nil
}

// ReadAll returns stored queries in raw form from internal file
func (storage *FileLogStorage) ReadAll() ([]byte, error) {
	return ioutil.ReadFile(storage.file.Name())
}

// WriteAll writes raw queries that need to be stored to internal file
func (storage *FileLogStorage) WriteAll(p []byte) error {
	storage.mutex.Lock()
	defer storage.mutex.Unlock()
	if err := storage.file.Truncate(0); err != nil {
		return err
	}
	_, err := storage.file.Write(p)
	if err != nil {
		return err
	}
	return nil
}

// Append appends raw queries to the end of internal file
func (storage *FileLogStorage) Append(p []byte) error {
	storage.mutex.Lock()
	defer storage.mutex.Unlock()
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
