package acracensor

type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) error
	Reset()
	GetName() string
}

type AcracensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
}
