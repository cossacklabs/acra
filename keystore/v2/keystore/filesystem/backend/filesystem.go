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
	versionPerm = os.FileMode(0644)
)

// Errors returned by DirectoryBackend:
var (
	ErrNotDirectory       = errors.New("root key directory is not a directory")
	ErrInvalidPermissions = errors.New("invalid key directory access permissions")
	ErrInvalidVersion     = errors.New("invalid key store version file content")
)

// DirectoryBackend keeps data in filesystem directory hierarchy.
type DirectoryBackend struct {
	root string
	log  *log.Entry
	lock *fileLock
}

const (
	lockFile      = ".lock"
	versionFile   = "version"
	versionString = "Acra Key Store v2"
)

// CreateDirectoryBackend opens a directory backend at given root path.
// The root directory will be created if it does not exist.
func CreateDirectoryBackend(root string) (*DirectoryBackend, error) {
	newLog := log.WithFields(log.Fields{
		"service":   serviceName,
		"subsystem": directorySubsystemName,
	})
	errLog := newLog.WithField("path", root)
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
	err = checkVersionFile(root)
	if err != nil {
		errLog.WithError(err).Debug("failed to create version file")
		return nil, err
	}
	lock, err := newFileLock(filepath.Join(root, lockFile))
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
	err = CheckDirectoryVersion(root)
	if err != nil {
		errLog.WithError(err).Debug("not a key store")
		return nil, err
	}
	lock, err := newFileLock(filepath.Join(root, lockFile))
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

func versionFilePath(rootDir string) string {
	return filepath.Join(rootDir, versionFile)
}

// CheckDirectoryVersion checks whether a key directory is of expected version.
func CheckDirectoryVersion(rootDir string) error {
	content, err := ioutil.ReadFile(versionFilePath(rootDir))
	if err != nil {
		return err
	}
	if string(content) != versionString {
		return ErrInvalidVersion
	}
	return nil
}

func checkVersionFile(rootDir string) error {
	// First, check whether we already have a valid version file. If so then we're done.
	// Otherwise, create a new version file if and only if it does not exist yet.
	// It might also be that the file has been removed, but we can't tell that for sure,
	// so just reinitialize the file in that case.
	err := CheckDirectoryVersion(rootDir)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return createVersionFile(rootDir)
}

func createVersionFile(rootDir string) (err error) {
	path := versionFilePath(rootDir)
	// Make sure the file does not exist and create it with proper mode.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, versionPerm)
	if err != nil {
		return err
	}
	// Close() might fail for newly written files, make sure we don't lose this error.
	defer func() {
		err2 := file.Close()
		if err == nil {
			err = err2
		}
	}()
	_, err = file.WriteString(versionString)
	if err != nil {
		return err
	}
	err = file.Sync()
	if err != nil {
		return err
	}
	return nil
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

// Accept either UNIX or Windows separator.
var pathSeparators = strings.NewReplacer(
	"/", string(os.PathSeparator),
	"\\", string(os.PathSeparator),
)

// Converts "key path" into "OS path" relative to the root directory.
func (b *DirectoryBackend) osPath(path string) (string, error) {
	fullPath := filepath.Join(b.root, pathSeparators.Replace(path))
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
	return b.lock.Lock()
}

// Unlock releases currently held exclusive lock.
func (b *DirectoryBackend) Unlock() error {
	return b.lock.Unlock()
}

// RLock acquires a shared lock on the store.
func (b *DirectoryBackend) RLock() error {
	return b.lock.RLock()
}

// RUnlock releases currently held shared lock.
func (b *DirectoryBackend) RUnlock() error {
	return b.lock.RUnlock()
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

// ListAll enumerates all paths currently stored.
// The paths are returned in lexicographical order.
func (b *DirectoryBackend) ListAll() ([]string, error) {
	paths := make([]string, 0)
	err := filepath.Walk(b.root, func(path string, info os.FileInfo, err error) error {
		// Immediately return an error if there's a problem walking the filesystem tree.
		if err != nil {
			return err
		}
		// filepath.Walk returns strings prefix with its first argument.
		path = strings.TrimPrefix(path, b.root+string(os.PathSeparator))
		// Skip special bookkeeping files that we have.
		if path == lockFile || path == versionFile {
			return nil
		}
		// Skip intermediate directories too.
		if info.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
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
