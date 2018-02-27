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
package base

import (
	"container/list"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

type PoisonCallback interface {
	Call() error
}

type StopCallback struct{}

func (*StopCallback) Call() error {
	log.Warningln("detected poison record, exit")
	os.Exit(1)
	return nil
}

type ExecuteScriptCallback struct {
	scriptPath string
}

func NewExecuteScriptCallback(path string) *ExecuteScriptCallback {
	return &ExecuteScriptCallback{scriptPath: path}
}
func (callback *ExecuteScriptCallback) Call() error {
	log.Warningf("detected poison record, run script - %v", callback.scriptPath)
	err := exec.Command(callback.scriptPath).Start()
	if err != nil {
		return err
	}
	return nil
}

/*
CallbackStorage store all callbacks in internal storage, on Call iterate
in sequence as insrted and call each callbacks until error or end of iterating
*/

type PoisonCallbackStorage struct {
	callbacks *list.List
}

func NewPoisonCallbackStorage() *PoisonCallbackStorage {
	return &PoisonCallbackStorage{callbacks: list.New()}
}
func (storage *PoisonCallbackStorage) AddCallback(callback PoisonCallback) {
	storage.callbacks.PushBack(callback)
}
func (storage *PoisonCallbackStorage) Call() error {
	var callback PoisonCallback
	for e := storage.callbacks.Front(); e != nil; e = e.Next() {
		callback = e.Value.(PoisonCallback)
		err := callback.Call()
		if err != nil {
			return err
		}
	}
	return nil
}

func (storage *PoisonCallbackStorage) HasCallbacks() bool {
	return storage.callbacks.Len() > 0
}
