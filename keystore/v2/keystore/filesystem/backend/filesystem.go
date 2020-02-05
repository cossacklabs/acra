/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package backend

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	log "github.com/sirupsen/logrus"
)

const serviceName = "keystore"
const directorySubsystemName = "directory-backend"

// Permissions used to create new files and directories.
// They are not enforced for existing storage since we verify integrity by other means.
const (
	keyDirPerm  = os.FileMode(0700)
	keyFilePerm = os.FileMode(0600)
)

// Errors returned by DirectoryBackend:
var (
	ErrNotDirectory       = errors.New("KeyStore: root directory is not a directory")
	ErrInvalidPermissions = errors.New("KeyStore: invalid access permissions")
)

// DirectoryBackend keeps data in filesystem directory hierarchy.
type DirectoryBackend struct {
	root string
	log  *log.Entry
	lock *os.File
}

const lockFile = ".lock"

// CreateDirectoryBackend opens a directory backend at given root path.
// The root directory will be created if it does not exist.
func CreateDirectoryBackend(root string) (*DirectoryBackend, error) {
	newLog := log.WithFields(log.Fields{
		"service":   serviceName,
		"subsystem": directorySubsystemName,
	})
	errLog := newLog.WithField("path", root)
	// Make sure the root directory stays the same even if somene changes current directory.
	root, err := filepath.Abs(root)
	if err != nil {
		errLog.WithError(err).Debug("failed to get absolute root key directory")
		return nil, err
	}
	fi, err := os.Stat(root)
	if err == nil {
		if !fi.IsDir() {
			errLog.Debug("root key directory is not a directory")
			return nil, ErrNotDirectory
		}
		if fi.Mode().Perm() != keyDirPerm {
			errLog.WithFields(log.Fields{
				"actual-perm":   fi.Mode().Perm(),
				"expected-perm": keyDirPerm,
			}).
				Debugf("invalid access permissions on root key directory")
			return nil, ErrInvalidPermissions
		}
	} else {
		if os.IsNotExist(err) {
			err = os.MkdirAll(root, keyDirPerm)
			if err != nil {
				errLog.WithError(err).Debug("failed to create root key directory")
				return nil, err
			}
		} else {
			errLog.WithError(err).Debug("failed to stat root key directory")
			return nil, err
		}
	}
	lock, err := os.Create(filepath.Join(root, lockFile))
	if err != nil {
		errLog.WithError(err).Debug("failed to create lock file")
		return nil, err
	}
	return &DirectoryBackend{
		root: root,
		log:  newLog,
		lock: lock,
	}, nil
}

// OpenDirectoryBackend opens an existing directory backend at given root path.
func OpenDirectoryBackend(root string) (*DirectoryBackend, error) {
	newLog := log.WithFields(log.Fields{
		"service":   serviceName,
		"subsystem": directorySubsystemName,
	})
	errLog := newLog.WithField("path", root)
	// Make sure the root directory stays the same even if somene changes current directory.
	root, err := filepath.Abs(root)
	if err != nil {
		errLog.WithError(err).Debug("failed to get absolute root key directory")
		return nil, err
	}
	fi, err := os.Stat(root)
	if err != nil {
		errLog.WithError(err).Debug("failed to stat root key directory")
		if os.IsNotExist(err) {
			err = api.ErrNotExist
		}
		return nil, err
	}
	if !fi.IsDir() {
		errLog.Debug("root key directory is not a directory")
		return nil, ErrNotDirectory
	}
	if fi.Mode().Perm() != keyDirPerm {
		errLog.WithFields(log.Fields{
			"actual-perm":   fi.Mode().Perm(),
			"expected-perm": keyDirPerm,
		}).
			Debugf("invalid access permissions on root key directory")
		return nil, ErrInvalidPermissions
	}
	lock, err := os.Create(filepath.Join(root, lockFile))
	if err != nil {
		errLog.WithError(err).Debug("failed to create lock file")
		return nil, err
	}
	return &DirectoryBackend{
		root: root,
		log:  newLog,
		lock: lock,
	}, nil
}

// Close this backend instance, freeing any associated resources.
func (b *DirectoryBackend) Close() error {
	err := b.lock.Close()
	if err != nil {
		// It's not a fatal error so we ignore it.
		b.log.WithError(err).Warn("failed to close lock file")
	}
	return nil
}

// Converts "key path" into "OS path" relative to the root directory.
func (b *DirectoryBackend) osPath(path string) (string, error) {
	if api.PathSeparator != string(os.PathSeparator) {
		path = strings.ReplaceAll(path, api.PathSeparator, string(os.PathSeparator))
	}
	fullPath := filepath.Join(b.root, path)
	// This is conservative check that "fullPath" is child of "b.root",
	// catching any funny "../../../.." that we might accidentally get.
	if fullPath != filepath.Clean(fullPath) {
		b.log.WithField("path", path).Warn("invalid key path used")
		return "", api.ErrInvalidPath
	}
	return fullPath, nil
}

// Lock acquires an exclusive lock on the store.
func (b *DirectoryBackend) Lock() error {
	return syscall.Flock(int(b.lock.Fd()), syscall.LOCK_EX)
}

// RLock acquires a shared lock on the store.
func (b *DirectoryBackend) RLock() error {
	return syscall.Flock(int(b.lock.Fd()), syscall.LOCK_SH)
}

// Unlock releases currently held lock.
func (b *DirectoryBackend) Unlock() error {
	return syscall.Flock(int(b.lock.Fd()), syscall.LOCK_UN)
}

// Get data at given path.
func (b *DirectoryBackend) Get(path string) ([]byte, error) {
	fullPath, err := b.osPath(path)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		b.log.WithError(err).WithField("path", fullPath).Debug("failed to read key data")
		if os.IsNotExist(err) {
			err = api.ErrNotExist
		}
		return nil, err
	}
	return data, nil
}

// Put data at given path.
func (b *DirectoryBackend) Put(path string, data []byte) error {
	fullPath, err := b.osPath(path)
	if err != nil {
		return err
	}

	directory := filepath.Dir(fullPath)
	err = os.MkdirAll(directory, keyDirPerm)
	if err != nil {
		b.log.WithError(err).WithField("path", directory).Debug("failed to create key directory")
		if os.IsNotExist(err) {
			err = api.ErrNotExist
		}
		return err
	}

	// Make sure the file does not exist before we add it.
	log := b.log.WithField("path", fullPath)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, keyFilePerm)
	if err != nil {
		log.WithError(err).Debug("failed to create key file")
		if os.IsExist(err) {
			err = api.ErrExist
		}
		return err
	}
	defer func() {
		if file != nil {
			err := file.Close()
			if err != nil {
				log.WithError(err).Debug("failed to close key file")
			}
			err = os.Remove(fullPath)
			if err != nil {
				log.WithError(err).Warn("failed to remove temporary key file")
			}
		}
	}()

	_, err = file.Write(data)
	if err != nil {
		log.WithError(err).Debug("failed to write key data")
		return err
	}
	err = file.Sync()
	if err != nil {
		log.WithError(err).Debug("failed to sync key data")
		return err
	}
	err = file.Close()
	if err != nil {
		log.WithError(err).Debug("failed to close key file")
		return err
	}

	file = nil
	return nil
}

// Rename oldpath into newpath.
func (b *DirectoryBackend) Rename(oldpath, newpath string) error {
	var err error
	oldpath, err = b.osPath(oldpath)
	if err != nil {
		return err
	}
	newpath, err = b.osPath(newpath)
	if err != nil {
		return err
	}
	err = os.Rename(oldpath, newpath)
	if err != nil {
		b.log.WithError(err).WithField("oldpath", oldpath).WithField("newpath", newpath).
			Debug("failed to rename key file")
		if os.IsNotExist(err) {
			err = api.ErrNotExist
		}
		return err
	}
	return nil
}

// RenameNX renames oldpath into newpath non-destructively.
func (b *DirectoryBackend) RenameNX(oldpath, newpath string) error {
	var err error
	oldpath, err = b.osPath(oldpath)
	if err != nil {
		return err
	}
	newpath, err = b.osPath(newpath)
	if err != nil {
		return err
	}
	err = b.doRenameNX(oldpath, newpath)
	if err != nil {
		b.log.WithError(err).WithField("oldpath", oldpath).WithField("newpath", newpath).
			Debug("failed to rename key file")
		if os.IsExist(err) {
			err = api.ErrExist
		}
		if os.IsNotExist(err) {
			err = api.ErrNotExist
		}
		return err
	}
	return nil
}

func (b *DirectoryBackend) doRenameNX(oldpath, newpath string) error {
	// Not all filesystems support "exclusive" rename and "os" API does not export
	// a function for such rename. We do not make atomicity promises in Backend,
	// but do our best to avoid race conditions here. Hard links should succeed
	// because key store should be located entirely on the same filesystem.
	err := os.Link(oldpath, newpath)
	if err != nil {
		return err
	}
	return os.Remove(oldpath)
}
