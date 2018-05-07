package acracensor

type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) error
	Reset()
	Release()
}

type AcracensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}
