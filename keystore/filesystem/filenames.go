/*
Copyright 2018, Cossack Labs Limited

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
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Default key folders' filenames
const (
	PoisonKeyFilename    = ".poison_key/poison_key"
	BasicAuthKeyFilename = "auth_key"
	historyDirSuffix     = ".old"
)

// GetZoneKeyFilename return filename for zone keys
func GetZoneKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

// getPublicKeyFilename
func getPublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s.pub", id)
}

// getZonePublicKeyFilename
func getZonePublicKeyFilename(id []byte) string {
	return getPublicKeyFilename([]byte(GetZoneKeyFilename(id)))
}

// getServerKeyFilename
func getServerKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_server", string(id))
}

// getTranslatorKeyFilename
func getTranslatorKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_translator", string(id))
}

// GetServerDecryptionKeyFilename return filename for decryption key
func GetServerDecryptionKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_storage", string(id))
}

// getConnectorKeyFilename
func getConnectorKeyFilename(id []byte) string {
	return string(id)
}

// getHistoryDirName returns name of the directory used to store history for given file name.
func getHistoryDirName(filename string) string {
	return filename + historyDirSuffix
}

// HistoricalFileNameTimeFormat format used as filename for rotated keys
const HistoricalFileNameTimeFormat = "2006-01-02T15:04:05.999999999"

// getNewHistoricalFileName returns a name of the file that can be used to store current content
// of the given file. It does *not* create or reserve the new file name.
func getNewHistoricalFileName(filename string) string {
	// This is a modified version of time.RFC3339Nano which does not include timezone information.
	// We use RFC 3339 (aka ISO 8601) so that timestamps can be easily sorted lexicographically.
	// Nanoseconds are included to minimize likelihood of collisions if the same key is rotated twice
	// within the same second. We use UTC and do not include trailing "Z" to not mess up the ordering.
	timestamp := time.Now().UTC().Format(HistoricalFileNameTimeFormat)
	return filepath.Join(getHistoryDirName(filename), timestamp)
}

// getHistoricalFilePaths returns paths to all versions of the current base file.
// "current" must be a valid path. Historical versions are returned from newest to oldest,
// starting with the current version.
func getHistoricalFilePaths(current string, storage Storage) ([]string, error) {
	historyDir := getHistoryDirName(current)
	history, err := storage.ReadDir(historyDir)
	// If the history directory does not exist then it's fine, we'll return only the current file.
	// But if we can't read existing history directory then something is wrong.
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	filenames := make([]string, 1, len(history)+1)
	filenames[0] = current
	// ReadDir() returns directory content in lexicographically sorted order. History files
	// have current time as a suffix so we need to reverse the order to move through them
	// from newest to oldest.
	for i := len(history) - 1; i >= 0; i-- {
		file := history[i]
		// We are interested in only regular files. Ignore directories, symlinks, etc.
		if (file.Mode() & os.ModeType) != 0 {
			continue
		}
		filenames = append(filenames, filepath.Join(historyDir, file.Name()))
	}
	return filenames, nil
}
