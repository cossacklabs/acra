/*
Copyright 2016, Cossack Labs Limited

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

package utils

import (
	"unicode"
	"unicode/utf8"
)

// IsPrintableEscapeChar returns true if character is ASCII printable (code between 32 and 126)
func IsPrintableEscapeChar(c byte) bool {
	if c >= 32 && c <= 126 {
		return true
	}
	return false
}

// IsPrintablePostgresqlString returns true if it's valid utf8 string
// except '\' character that used as escape character in strings
func IsPrintablePostgresqlString(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	// convert byte slice to string to work with Runes instead of bytes
	stringValue := BytesToString(data)
	// '\' is special case because PostgreSQL escapes it
	for _, c := range stringValue {
		if (unicode.IsControl(c) && !unicode.IsSpace(c)) || c == '\\' {
			return false
		}
	}
	return true
}
