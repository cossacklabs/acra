/*
Copyright 2020, Cossack Labs Limited

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

package pseudonymization

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type cryptoRandomSource struct{}

func (s cryptoRandomSource) Seed(seed int64) {}

func (s cryptoRandomSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (s cryptoRandomSource) Uint64() (v uint64) {
	err := binary.Read(rand.Reader, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}
	return v
}

var seededRand *mrand.Rand = mrand.New(cryptoRandomSource{})

func randomString(buf []byte) error {
	// Random string in generated in this way -- as opposed to calling Read() and processing the
	// resulting buffer -- to achieve uniform distribution of probability of characters selected
	// from "charset". This is important to minimize possible collisions in token generation.
	for i := 0; i < len(buf); i++ {
		buf[i] = charset[seededRand.Intn(len(charset))]
	}
	return nil
}

var (
	genericTLDs = []string{".com", ".net", ".org", ".edu", ".info"}
	ccTLDs      = []string{".au", ".br", ".de", ".jp", ".et", ".us"}
	allTLDs     = append(genericTLDs, ccTLDs...)
)

func randomEmail(buf []byte) error {
	// If the buffer is really short, choose only among 2-letter country TLDs so that we have some space for other parts.
	tlds := allTLDs
	if len(buf) < len("a@b.cdef") {
		tlds = ccTLDs
	}
	tld := []byte(tlds[seededRand.Int31n(int32(len(tlds)))])
	// After we've chosen the TLD, fill the rest of the email with gibberish, and throw @ in there somewhere.
	nonTLDlen := len(buf) - len(tld)
	err := randomString(buf[:nonTLDlen])
	if err != nil {
		return err
	}
	buf[nonTLDlen/2] = '@'
	copy(buf[nonTLDlen:], tld)
	return nil
}

func randomRead(buf []byte) error {
	n, err := rand.Read(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return errors.New("can't generate enough random data")
	}
	return nil
}
