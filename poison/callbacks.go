/*
Copyright 2016, Cossack Labs Limited

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

package poison

import (
	"container/list"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

// EmptyCallback implements Callback and log message to show that RecordProcessor works
type EmptyCallback struct{}

// Call log on Call
func (EmptyCallback) Call() error {
	log.Warningln("Recognized poison record")
	return nil
}

// StopCallback represents special action to call if service should quit on detecting poison record
type StopCallback struct{}

// Call exists service with log
func (*StopCallback) Call() error {
	log.WithField(logging.FieldKeyEventCode, logging.EventCodePoisonRecordDetectionMessage).Warningln("Detected poison record, exit")
	os.Exit(1)
	log.WithField(logging.FieldKeyEventCode, logging.EventCodePoisonRecordDetectionMessage).Errorln("executed code after os.Exit")
	return nil
}

// ExecuteScriptCallback represents what script to call on detecting poison record
type ExecuteScriptCallback struct {
	scriptPath string
}

// NewExecuteScriptCallback returns callback for script execution
func NewExecuteScriptCallback(path string) *ExecuteScriptCallback {
	return &ExecuteScriptCallback{scriptPath: path}
}

// Call runs from scriptPath on detecting poison record
func (callback *ExecuteScriptCallback) Call() error {
	log.Warningf("detected poison record, run script - %v", callback.scriptPath)
	err := exec.Command(callback.scriptPath).Start()
	if err != nil {
		return err
	}
	return nil
}

// CallbackStorage stores all callbacks in internal storage, on Call iterates
// and calls each callbacks until error or end of iterating
type CallbackStorage struct {
	callbacks *list.List
}

// NewCallbackStorage creates new CallbackStorage
func NewCallbackStorage() *CallbackStorage {
	return &CallbackStorage{callbacks: list.New()}
}

// AddCallback adds callback to end of list
func (storage *CallbackStorage) AddCallback(callback base.Callback) {
	storage.callbacks.PushBack(callback)
}

// Call calls all callbacks in sequence
func (storage *CallbackStorage) Call() error {
	var callback base.Callback
	for e := storage.callbacks.Front(); e != nil; e = e.Next() {
		callback = e.Value.(base.Callback)
		err := callback.Call()
		if err != nil {
			return err
		}
	}
	return nil
}

// HasCallbacks returns number of callbacks in storage
func (storage *CallbackStorage) HasCallbacks() bool {
	return storage.callbacks.Len() > 0
}
