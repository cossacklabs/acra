package acracensor

import log "github.com/sirupsen/logrus"

type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) (bool, error) //1st return arg specifies whether continue verification or not, 2nd specifies whether query is forbidden
	Release()
}

type AcraCensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}

//global logging object for censor
var Logger = log.WithFields(log.Fields{"service": "acra-censor"})
