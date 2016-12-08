// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils_test

import (
	"github.com/cossacklabs/acra/utils"
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {
	test_path := "/tmp/testfilepath"
	exists, err := utils.FileExists(test_path)
	if exists || err != nil {
		t.Fatalf("File exists or returned any error. err = %v\n", err)
	}
	_, err = os.Create(test_path)
	defer os.Remove(test_path)
	if err != nil {
		t.Fatalf("Can't create test temporary file %v. err - %v\n", test_path, err)
	}
	exists, err = utils.FileExists(test_path)
	if !exists || err != nil {
		t.Fatalf("File not exists or returned any error. err = %v\n", err)
	}
}

func TestFindTag(t *testing.T) {
	symbol := byte('1')
	count := 4
	test_data := []byte("11110000")
	if utils.FindTag(symbol, count, test_data) != 0 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("01111000")
	if utils.FindTag(symbol, count, test_data) != 1 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("00111100")
	if utils.FindTag(symbol, count, test_data) != 2 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("00011110")
	if utils.FindTag(symbol, count, test_data) != 3 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("00001111")
	if utils.FindTag(symbol, count, test_data) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("10101111")
	if utils.FindTag(symbol, count, test_data) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("01101111")
	if utils.FindTag(symbol, count, test_data) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("11101111")
	if utils.FindTag(symbol, count, test_data) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("11101101")
	if utils.FindTag(symbol, count, test_data) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}

	test_data = []byte("111")
	if utils.FindTag(symbol, count, test_data) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}
	test_data = []byte{}
	if utils.FindTag(symbol, count, test_data) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}
	test_data = []byte("1111")
	if utils.FindTag(symbol, count, test_data) != 0 {
		t.Fatal("Incorrectly found tag")
	}

	count = 8
	test_data = []byte("111111110000000000")
	if utils.FindTag(symbol, count, test_data) != 0 {
		t.Fatal("Incorrectly found tag")
	}
}
