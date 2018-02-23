package firewall

import (
	"errors"
)

type FilesystemAcraFirewall struct {

	handlers []QueryHandler

	storageDirectory string
}


var ErrHandlersNotSpecified = errors.New("at least one query handler should be specified")


func NewFilesystemAcraFirewall(storageDirectory string) (*FilesystemAcraFirewall, error) {

	return &FilesystemAcraFirewall{storageDirectory:storageDirectory}, nil
}


func (firewall *FilesystemAcraFirewall) AddSpecificHandler(handler QueryHandler){

	firewall.handlers = append(firewall.handlers, handler)
}

func (firewall *FilesystemAcraFirewall) HandleQuery(query string) error{

	if len(firewall.handlers) < 1 {
		return ErrHandlersNotSpecified
	}

	for _, handler := range firewall.handlers{
		if err := handler.CheckQuery(query); err != nil{
			return err
		}
	}
	return nil
}