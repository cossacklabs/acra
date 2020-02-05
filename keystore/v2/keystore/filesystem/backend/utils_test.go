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

package backend

import (
	"reflect"
	"testing"
)

func TestSplitJoin(t *testing.T) {
	checkJoin := func(actual, expected string) {
		if actual != expected {
			t.Errorf("invalid path join, actual: %v, expected: %v", actual, expected)
		}
	}
	checkJoin(JoinPath(""), "")
	checkJoin(JoinPath("a"), "a")
	checkJoin(JoinPath("a", "b"), "a/b")
	checkJoin(JoinPath("a", "b", "c"), "a/b/c")
	checkJoin(JoinPath("a", "/", ".."), "a///..")

	checkSplit := func(actual, expected []string) {
		if !reflect.DeepEqual(actual, expected) {
			t.Errorf("invalid path join, actual: %v, expected: %v", actual, expected)
		}
	}
	checkSplit(SplitPath(""), []string{""})
	checkSplit(SplitPath("a"), []string{"a"})
	checkSplit(SplitPath("a/b"), []string{"a", "b"})
	checkSplit(SplitPath("a/b/c"), []string{"a", "b", "c"})
	checkSplit(SplitPath("a///c/.."), []string{"a", "", "", "c", ".."})
}
