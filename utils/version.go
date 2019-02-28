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
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// VERSION is current Acra suite version
// store it as string instead initialized struct value to easy change/grep/sed/replace value via scripts or with
// -ldflags "-X github.com/cossacklabs/acra/utils.VERSION=X.X.X"
var VERSION = "0.84.2"

// Version store version info
type Version struct {
	Major string
	Minor string
	Patch string
}

// ComparisonStatus result of comparison versions
type ComparisonStatus int

// Available constant values for ComparisonStatus
const (
	Less    ComparisonStatus = iota - 1 // -1
	Equal                               // 0
	Greater                             // 1
)

// Compare compare v with v2 and return ComparisonStatus [Less|Equal|Greater]
func (v *Version) Compare(v2 *Version) ComparisonStatus {
	if res := strings.Compare(v.Major, v2.Major); res != int(Equal) {
		return ComparisonStatus(res)
	}
	if res := strings.Compare(v.Minor, v2.Minor); res != int(Equal) {
		return ComparisonStatus(res)
	}
	return ComparisonStatus(strings.Compare(v.Patch, v2.Patch))
}

// String format version as string
func (v *Version) String() string {
	return fmt.Sprintf("%s.%s.%s", v.Major, v.Minor, v.Patch)
}

// MajorAsFloat64 return major number as float64
func (v *Version) MajorAsFloat64() (float64, error) {
	return strconv.ParseFloat(v.Major, 64)
}

// MinorAsFloat64 return minor number as float64
func (v *Version) MinorAsFloat64() (float64, error) {
	return strconv.ParseFloat(v.Minor, 64)
}

// PatchAsFloat64 return patch number as float64
func (v *Version) PatchAsFloat64() (float64, error) {
	return strconv.ParseFloat(v.Patch, 64)
}

const (
	major = iota
	minor
	patch
)

// ErrInvalidVersionFormat error for incorrectly formatted version value
var ErrInvalidVersionFormat = errors.New("value has incorrect format (semver 2.0.0 format expected, https://semver.org/)")

// ParseVersion and return as struct
func ParseVersion(version string) (*Version, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidVersionFormat
	}
	for _, part := range parts {
		// validate that version has correct values
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return nil, err
		}
	}
	return &Version{parts[major], parts[minor], parts[patch]}, nil
}

// GetParsedVersion return version as Version struct
func GetParsedVersion() (*Version, error) {
	return ParseVersion(VERSION)
}
