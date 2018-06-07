package acracensor

type QueryHandlerInterface interface {
	//1st return arg specifies whether continue verification or not, 2nd specifies whether query is forbidden
	CheckQuery(sqlQuery string) (bool, error)
	Reset()
	Release()
	Priority() int
}

type AcraCensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}
