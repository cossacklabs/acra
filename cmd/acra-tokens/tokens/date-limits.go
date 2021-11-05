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

package tokens

import (
	"errors"
	"flag"
	"time"

	log "github.com/sirupsen/logrus"
)

// CommonDateParameters is a mix-in of command line parameters for date limits.
type CommonDateParameters struct {
	accessedAfter  string
	accessedBefore string
	createdAfter   string
	createdBefore  string

	accessedAfterTime  time.Time
	accessedBeforeTime time.Time
	createdAfterTime   time.Time
	createdBeforeTime  time.Time
}

// Date formats to accept in command-line parameters.
// These are basically variations on ISO 8601.
var acceptedDateFormats = []string{
	"2006-01-02T15:04:05Z07:00", // Full RFC 3339
	"2006-01-02T15:04:05",       // Various truncations
	"2006-01-02 15:04:05",
	"2006-01-02T15:04",
	"2006-01-02 15:04",
	"2006-01-02",
	"Jan 2006",
	"January 2006",
	"2006",
}

// ErrInvalidDateTime is returned when we can't parse the time string provided by the user.
var ErrInvalidDateTime = errors.New("unrecognized date format")

// Parse date-time string in more human-friendly way: try multiple date formats
// and use local timezone (not UTC) unless it's specified explicitly.
func parseDateTime(datetime string) (t time.Time, err error) {
	for _, format := range acceptedDateFormats {
		t, err = time.ParseInLocation(format, datetime, time.Local)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, ErrInvalidDateTime
}

// Register registers token storage flags with the given flag set.
func (p *CommonDateParameters) Register(flags *flag.FlagSet) {
	flags.StringVar(&p.accessedAfter, "accessed_after", "", "limit action to tokens accessed after specified date")
	flags.StringVar(&p.accessedBefore, "accessed_before", "", "limit action to tokens accessed before specified date")
	flags.StringVar(&p.createdAfter, "created_after", "", "limit action to tokens created after specified date")
	flags.StringVar(&p.createdBefore, "created_before", "", "limit action to tokens created before specified date")
}

// Validate date limit parameters.
func (p *CommonDateParameters) Validate() error {
	var err error
	if p.accessedAfter != "" {
		p.accessedAfterTime, err = parseDateTime(p.accessedAfter)
		if err != nil {
			log.WithError(err).Warning("Invalid date for --accessed_after")
			return err
		}
	}
	if p.accessedBefore != "" {
		p.accessedBeforeTime, err = parseDateTime(p.accessedBefore)
		if err != nil {
			log.WithError(err).Warning("Invalid date for --accessed_before")
			return err
		}
	}
	if p.createdAfter != "" {
		p.createdAfterTime, err = parseDateTime(p.createdAfter)
		if err != nil {
			log.WithError(err).Warning("Invalid date for --created_after")
			return err
		}
	}
	if p.createdBefore != "" {
		p.createdBeforeTime, err = parseDateTime(p.createdBefore)
		if err != nil {
			log.WithError(err).Warning("Invalid date for --created_before")
			return err
		}
	}
	return nil
}

// AccessedWithinLimits returns true if the access time is within specified limits.
func (p *CommonDateParameters) AccessedWithinLimits(accessTime time.Time) bool {
	if p.accessedAfter != "" {
		if accessTime.Before(p.accessedAfterTime) {
			return false
		}
	}
	if p.accessedBefore != "" {
		if accessTime.After(p.accessedBeforeTime) {
			return false
		}
	}
	return true
}

// CreatedWithinLimits returns true if the creation time is within specified limits.
func (p *CommonDateParameters) CreatedWithinLimits(creationTime time.Time) bool {
	if p.createdAfter != "" {
		if creationTime.Before(p.createdAfterTime) {
			return false
		}
	}
	if p.createdBefore != "" {
		if creationTime.After(p.createdBeforeTime) {
			return false
		}
	}
	return true
}
