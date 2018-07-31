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

// Package handlers contains all query handlers for AcraCensor:
// blacklist handler, which allows everything and forbids something specific;
// whitelist handler, which allows something and restricts/forbids everything else;
// ignore handler, which allows to ignore any query;
// and querycapture module that logs every unique query to the QueryCapture log.
//
// https://github.com/cossacklabs/acra/wiki/AcraCensor
package handlers

import (
	"strings"
	"testing"
)

func TestUtilities(t *testing.T) {

	//Test 1
	expected := []string{"x", "y", "z"}

	input := []string{"x", "y", "z", "x", "y"}

	output := removeDuplicates(input)

	if !areEqual(output, expected) {
		t.Fatal("unexpected result")
	}

	//Test 2
	expected = []string{"@lagovas", "@vixentael", "@secumod"}

	input = []string{"@lagovas", "@vixentael", "@secumod", "@lagovas", "@vixentael", "@secumod", "@lagovas", "@vixentael", "@secumod"}

	output = removeDuplicates(input)

	if !areEqual(output, expected) {
		t.Fatal("unexpected result")
	}

}

func areEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for index := 0; index < len(a); index++ {
		if !strings.EqualFold(a[index], b[index]) {
			return false
		}
	}

	return true
}
