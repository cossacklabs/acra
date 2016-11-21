package acra

import (
	"container/list"
	"log"
	"os"
	"os/exec"
)

type PoisonCallback interface {
	Call() error
}

type StopCallback struct{}

func (*StopCallback) Call() error {
	log.Println("Error: detected poison record, exit")
	os.Exit(1)
	return nil
}

type ExecuteScriptCallback struct {
	script_path string
}

func NewExecuteScriptCallback(path string) *ExecuteScriptCallback {
	return &ExecuteScriptCallback{script_path: path}
}
func (callback *ExecuteScriptCallback) Call() error {
	log.Printf("Warning: detected poison record, run script - %v\n", callback.script_path)
	err := exec.Command(callback.script_path).Start()
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
