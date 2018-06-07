package acracensor

type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) (bool, error) //1st return arg specifies whether continue verification or not, 2nd specifies whether query is forbidden
	Reset()
	Release()
	Priority() int //Priority is used for managing queue of processed handlers. Least number (starting from 0) specifies most prioritized handler while processing
}

type AcraCensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}
