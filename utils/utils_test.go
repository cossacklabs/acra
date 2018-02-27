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
	testPath := "/tmp/testfilepath"
	exists, err := utils.FileExists(testPath)
	if exists || err != nil {
		t.Fatalf("File exists or returned any error. err = %v\n", err)
	}
	_, err = os.Create(testPath)
	defer os.Remove(testPath)
	if err != nil {
		t.Fatalf("can't create test temporary file %v. err - %v\n", testPath, err)
	}
	exists, err = utils.FileExists(testPath)
	if !exists || err != nil {
		t.Fatalf("File not exists or returned any error. err = %v\n", err)
	}
}

func TestFindTag(t *testing.T) {
	symbol := byte('1')
	count := 4
	testData := []byte("11110000")
	if utils.FindTag(symbol, count, testData) != 0 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("01111000")
	if utils.FindTag(symbol, count, testData) != 1 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("00111100")
	if utils.FindTag(symbol, count, testData) != 2 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("00011110")
	if utils.FindTag(symbol, count, testData) != 3 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("00001111")
	if utils.FindTag(symbol, count, testData) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("10101111")
	if utils.FindTag(symbol, count, testData) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("01101111")
	if utils.FindTag(symbol, count, testData) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("11101111")
	if utils.FindTag(symbol, count, testData) != 4 {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("11101101")
	if utils.FindTag(symbol, count, testData) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}

	testData = []byte("111")
	if utils.FindTag(symbol, count, testData) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}
	testData = []byte{}
	if utils.FindTag(symbol, count, testData) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}
	testData = []byte("1111")
	if utils.FindTag(symbol, count, testData) != 0 {
		t.Fatal("Incorrectly found tag")
	}

	count = 8
	testData = []byte("111111110000000000")
	if utils.FindTag(symbol, count, testData) != 0 {
		t.Fatal("Incorrectly found tag")
	}

	count = 8
	testData = []byte("11111110000000000")
	if utils.FindTag(symbol, count, testData) != utils.NOT_FOUND {
		t.Fatal("Incorrectly found tag")
	}
}
