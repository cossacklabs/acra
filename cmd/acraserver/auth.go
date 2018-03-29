// Copyright 2018, Cossack Labs Limited
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

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"github.com/cossacklabs/acra/utils"
)

func getAuthData(authPath string) (data []byte, err error) {
	configPath, err := utils.AbsPath(authPath)
	if err != nil {
		return nil, err
	}
	exists, err := utils.FileExists(configPath)
	if err != nil {
		return nil, err
	}
	if exists {
		fileContent, err := ioutil.ReadFile(configPath)
		if err != nil {
			return nil, err
		}
		data = fileContent
		return data, nil
	}

	return nil, errors.New(fmt.Sprintf("No auth config [%v]", authPath))
}
