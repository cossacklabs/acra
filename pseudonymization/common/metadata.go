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

package common

import (
	"time"

	"github.com/golang/protobuf/proto"
)

// TokenMetadata is additional bookeeping information kept by TokenStorage along with the token value.
type TokenMetadata struct {
	Created  time.Time
	Accessed time.Time
	Disabled bool
}

// NewTokenMetadata creates metadata for a newly created token entry,
func NewTokenMetadata() TokenMetadata {
	now := time.Now().UTC()
	return TokenMetadata{Created: now, Accessed: now, Disabled: false}
}

// AccessedBefore checks that the token has been accessed before the specified time instance with given granularity.
func (t *TokenMetadata) AccessedBefore(instant time.Time, granularity time.Duration) bool {
	return t.Accessed.Before(instant.Add(-granularity))
}

// Equal returns true if this metadata is equal to the other one.
func (t TokenMetadata) Equal(other TokenMetadata) bool {
	return t.Created.Equal(other.Created) && t.Accessed.Equal(other.Accessed) && t.Disabled == other.Disabled
}

// EmbedMetadata composes data with additional metadata into a single byte slice.
func EmbedMetadata(data []byte, metadata TokenMetadata) []byte {
	value := MetadataContainer{
		Data:     data,
		Created:  metadata.Created.Unix(),
		Accessed: metadata.Accessed.Unix(),
		Disabled: metadata.Disabled,
	}
	bytes, _ := proto.Marshal(&value)
	return bytes
}

// ExtractMetadata extracts data and metadata back from a composite byte slice.
func ExtractMetadata(data []byte) ([]byte, TokenMetadata, error) {
	var value MetadataContainer
	err := proto.Unmarshal(data, &value)
	if err != nil {
		return nil, TokenMetadata{}, err
	}
	metadata := TokenMetadata{
		Created:  time.Unix(value.Created, 0),
		Accessed: time.Unix(value.Accessed, 0),
		Disabled: value.Disabled,
	}
	return value.Data, metadata, nil
}
