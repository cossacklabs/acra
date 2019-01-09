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

package cmd

import "golang.org/x/crypto/argon2"

// InitArgon2Params returns default Argon2 params
func InitArgon2Params() Argon2Params {
	var p Argon2Params
	p.Time = uint32(DefaultWebConfigAuthArgon2Time)
	p.Memory = uint32(DefaultWebConfigAuthArgon2Memory)
	p.Threads = uint8(DefaultWebConfigAuthArgon2Threads)
	p.Length = uint32(DefaultWebConfigAuthArgon2Length)
	return p
}

// HashArgon2 returns hashed password with provided salt and params
func HashArgon2(password string, salt string, p Argon2Params) (hash []byte, err error) {
	passwordBytes := argon2.IDKey([]byte(password), []byte(salt),
		p.Time,
		p.Memory,
		p.Threads,
		p.Length)
	if err != nil {
		return
	}
	return passwordBytes, nil
}
