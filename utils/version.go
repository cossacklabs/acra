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
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
	"strings"
	"sync"
)

// VERSION is current Acra suite version
// store it as string instead initialized struct value to easy change/grep/sed/replace value via scripts
var VERSION = "0.84.2"

// Version store version info
type Version struct {
	Major string
	Minor string
	Patch string
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
var ErrInvalidVersionFormat = errors.New("VERSION value has incorrect format (semver expected)")

// GetParsedVersion return version as Version struct
func GetParsedVersion() (*Version, error) {
	parts := strings.Split(VERSION, ".")
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

var registerLock = sync.Once{}

// serviceNameToLabelFormat convert service name to lower case and remove all '_'
// ex. Acra-Server will be changed to acraserver
func serviceNameToLabelFormat(serviceName string) string {
	const replaceAll = -1
	return strings.ToLower(strings.Replace(serviceName, "-", "", replaceAll))
}

// RegisterVersionMetrics set and register metrics with current version value
func RegisterVersionMetrics(serviceName string) {
	labelServiceName := serviceNameToLabelFormat(serviceName)
	majorVersionGauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_major", labelServiceName),
			Help: "Major number of version",
		}, []string{})

	minorVersionGauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_minor", labelServiceName),
			Help: "Minor number of version",
		}, []string{})

	patchVersionGauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_patch", labelServiceName),
			Help: "Patch number of version",
		}, []string{})

	version, err := GetParsedVersion()
	if err != nil {
		panic(err)
	}

	if val, err := version.MajorAsFloat64(); err == nil {
		majorVersionGauge.With(nil).Set(val)
	} else {
		panic(err)
	}

	if val, err := version.MinorAsFloat64(); err == nil {
		minorVersionGauge.With(nil).Set(val)
	} else {
		panic(err)
	}

	if val, err := version.PatchAsFloat64(); err == nil {
		patchVersionGauge.With(nil).Set(val)
	} else {
		panic(err)
	}

	registerLock.Do(func() {
		prometheus.MustRegister(majorVersionGauge)
		prometheus.MustRegister(minorVersionGauge)
		prometheus.MustRegister(patchVersionGauge)
	})
}
