/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package filesystem

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Storage interface provides support for alternative filesystem-like storage backends of KeyStore.
// Semantics of methods are identical to corresponding "os", "io", "io/ioutil" functions where applicable.
type Storage interface {
	// Stat a file at given path.
	Stat(path string) (os.FileInfo, error)
	// Exists checks whether a file exists at a given path.
	Exists(path string) (bool, error)
	// ReadDir reads a directory and returns information about its contents.
	ReadDir(path string) ([]os.FileInfo, error)
	// MkdirAll creates directory at given path with given permissions, including all missing intermediate directories.
	// It is not at error if a directory already exists at this path.
	MkdirAll(path string, perm os.FileMode) error
	// Rename a file atomically from oldpath to newpath, replacing a file at newpath if it exists.
	Rename(oldpath, newpath string) error
	// TempFile creates a new temporary file with given name pattern and access permissions.
	// Name of the newly created file is returned.
	// Caller is responsible for removing the file once they are done with it.
	TempFile(pattern string, perm os.FileMode) (string, error)
	// TempDir creates a new temporary directory with given name pattern and access permissions.
	// Name of the newly created directory is returned.
	// Caller is responsible for removing the directory and its contents once they are done with it.
	TempDir(pattern string, perm os.FileMode) (string, error)
	// Link creates a hard link at newpath which refers to the same path as oldpath.
	// Not all file systems support hard links, and there may be restrictions on hard links between different directories.
	Link(oldpath, newpath string) error
	// Copy a file from src to dst, preserving access mode.
	// It is an error if dst already exists.
	// dst is an independent copy of src with initially identical content.
	Copy(src, dst string) error
	// ReadFile reads entire content of the specified file.
	ReadFile(path string) ([]byte, error)
	// WriteAll replaces entire content of the specified file, creating it with specified mode if it does not exist.
	WriteFile(path string, data []byte, perm os.FileMode) error
	// Remove the file or empty directory at given path.
	Remove(path string) error
	// RemoveAll removes the path with any children that it contains.
	RemoveAll(path string) error
}

// DummyStorage keeps key files in filesystem directories.
type DummyStorage struct{ fileStorage }

type fileStorage struct{}

func (*fileStorage) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (*fileStorage) Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (*fileStorage) ReadDir(path string) ([]os.FileInfo, error) {
	return ioutil.ReadDir(path)
}

func (*fileStorage) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (*fileStorage) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (*fileStorage) TempFile(pattern string, perm os.FileMode) (string, error) {
	tmp, err := ioutil.TempFile(filepath.Dir(pattern), filepath.Base(pattern))
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	err = tmp.Chmod(perm)
	if err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

func (*fileStorage) TempDir(pattern string, perm os.FileMode) (string, error) {
	path, err := ioutil.TempDir(filepath.Dir(pattern), filepath.Base(pattern))
	if err != nil {
		return "", err
	}
	err = os.Chmod(path, perm)
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func (*fileStorage) Link(oldpath, newpath string) error {
	return os.Link(oldpath, newpath)
}

func (*fileStorage) Copy(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	fi, err := srcFile.Stat()
	if err != nil {
		return err
	}
	perm := fi.Mode() & os.ModePerm

	// Make sure we *do not* overwrite the file if something is already there
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if err2 := dstFile.Close(); err == nil {
			err = err2
		}
	}()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	err = dstFile.Sync()
	if err != nil {
		return err
	}

	// not nil to report deferred Close() errors
	return err
}

func (*fileStorage) ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func (*fileStorage) WriteFile(path string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(path, data, perm)
}

func (*fileStorage) Remove(path string) error {
	return os.Remove(path)
}

func (*fileStorage) RemoveAll(path string) error {
	return os.RemoveAll(path)
}
