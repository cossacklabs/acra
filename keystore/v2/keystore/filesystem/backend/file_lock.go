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
	"os"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// fileLock is an interprocess read-write lock that serializes access to filesystem.
//
// This lock is implemented with BSD flock(2) and has corresponding semantics.
//
// Note that this is an advisory lock. That is, this lock can be used to guard
// access to some filesystem resource by cooperating processes, but it does not
// guarantee correct serialization of filesystem accesses by itself.
//
// Also note that flock(2) has subtly different semantics from POSIX record locks
// created by fcntl(2). Read corresponding system manual pages for details.
type fileLock struct {
	lockFile *os.File
	path     string
	// Here's a thing: BSD file locks are per-process. That is, they are shared
	// between threads like fds. Furthermore, they can be 'transparently'
	// upgraded: if the process holds a shared lock and grabs it again as exclusive,
	// the system will upgrade the lock to exclusive (possibly by releasing and
	// re-grabbing it). This is not what we want, so keep a regular lock here
	// to make sure that goroutines are correctly synchronized among themselves.
	lockSync sync.Mutex
}

// newFileLock creates a lock anchored at given file path.
func newFileLock(path string) (*fileLock, error) {
	lock, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &fileLock{lockFile: lock, path: path}, nil
}

// Close the lock. This releases the lock if it is held.
func (l *fileLock) Close() error {
	return l.lockFile.Close()
}

// We need to juggle *two* locks here -- the mutex and the file lock -- and
// this is hard. So hard that we are using a regular sync.Mutex here rather
// than seemingly more natural sync.RWMutex. Lock contention within the
// process should be fairly minimal, and different processes still use the
// read-write semantics, so it's okay.
//
// The reason for this complexity is that unlocking the flock can fail and
// this leaves the flock in a broken state for this process. We still unlock
// the local mutex to prevent the deadlock, but the flock is placed into
// a special "poisoned" state. We will (try to) recover from the poisoned
// state the next time the lock is grabbed.
//
// Checking for poisoning needs only a read lock, but poisoning and recovery
// require write lock to be held. This means that we might need a write lock
// when the user call RLock(). Upgrading and downgrading sync.RWMutex is hard
// to do correctly so we go with a simple synx.Mutex instead.

func (l *fileLock) isPoisoned() bool {
	return l.lockFile == nil
}

func (l *fileLock) poisonLock(reason error) {
	log := log.WithField("path", l.path)
	log.WithError(reason).Warn("Poisoning lock")
	err := l.lockFile.Close()
	if err != nil {
		// We can't do much about an error here and we can't use the file anymore.
		log.WithError(err).Warn("Failed to close poisoned lock")
	}
	l.lockFile = nil
}

func (l *fileLock) recoverLock() error {
	log.WithField("path", l.path).Warn("Recovering poisoned lock")
	newLockFile, err := os.Create(l.path)
	if err != nil {
		return err
	}
	l.lockFile = newLockFile
	return nil
}

func (l *fileLock) Lock() error {
	l.lockSync.Lock()
	if l.isPoisoned() {
		err := l.recoverLock()
		if err != nil {
			l.lockSync.Unlock()
			return err
		}
	}
	err := syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		l.lockSync.Unlock()
		return err
	}
	return nil
}

func (l *fileLock) Unlock() error {
	defer l.lockSync.Unlock()
	err := syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_UN)
	if err != nil {
		l.poisonLock(err)
		return err
	}
	return nil
}

func (l *fileLock) RLock() error {
	l.lockSync.Lock()
	if l.isPoisoned() {
		err := l.recoverLock()
		if err != nil {
			l.lockSync.Unlock()
			return err
		}
	}
	err := syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_SH)
	if err != nil {
		l.lockSync.Unlock()
		return err
	}
	return nil
}

func (l *fileLock) RUnlock() error {
	defer l.lockSync.Unlock()
	err := syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_UN)
	if err != nil {
		l.poisonLock(err)
		return err
	}
	return nil
}
