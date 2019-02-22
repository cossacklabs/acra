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
	Major uint32
	Minor uint32
	Patch uint32
}

type ComparisonStatus int

const (
	Less    ComparisonStatus = iota - 1 // -1
	Equal                               // 0
	Greater                             // 1
)

func compareUint32(v1, v2 uint32) ComparisonStatus {
	res := v1 - v2
	if res == 0 {
		return Equal
	}
	if res < 0 {

		return Less
	}
	return Greater
}

// Compare compare v with v2 and return ComparisonStatus [Less|Equal|Greater]
func (v *Version) Compare(v2 *Version) ComparisonStatus {
	if res := compareUint32(v.Major, v2.Major); res != Equal {
		return res
	}
	if res := compareUint32(v.Minor, v2.Minor); res != Equal {
		return res
	}
	return compareUint32(v.Major, v2.Major)
}

// String format version as string
func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// MajorAsFloat64 return major number as float64
func (v *Version) MajorAsFloat64() (float64, error) {
	return float64(v.Major), nil
}

// MinorAsFloat64 return minor number as float64
func (v *Version) MinorAsFloat64() (float64, error) {
	return float64(v.Minor), nil
}

// PatchAsFloat64 return patch number as float64
func (v *Version) PatchAsFloat64() (float64, error) {
	return float64(v.Patch), nil
}

const (
	major = iota
	minor
	patch
)

// ErrInvalidVersionFormat error for incorrectly formatted version value
var ErrInvalidVersionFormat = errors.New("VERSION value has incorrect format (semver 2.0.0 format expected, https://semver.org/)")

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
	majorValue, err := strconv.ParseUint(parts[major], 10, 32)
	if err != nil {
		return nil, err
	}
	minorValue, err := strconv.ParseUint(parts[minor], 10, 32)
	if err != nil {
		return nil, err
	}
	patchValue, err := strconv.ParseUint(parts[patch], 10, 32)
	if err != nil {
		return nil, err
	}
	return &Version{uint32(majorValue), uint32(minorValue), uint32(patchValue)}, nil
}

// GetParsedVersion return version as Version struct
func GetParsedVersion() (*Version, error) {
	return ParseVersion(VERSION)
}
