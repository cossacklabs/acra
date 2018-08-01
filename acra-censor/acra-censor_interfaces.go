package acracensor

//QueryHandlerInterface describes what actions are available for queries.
type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) (bool, error) //1st return arg specifies whether continue verification or not, 2nd specifies whether query is forbidden
	Release()
}

//Interface describes main AcraCensor methods: adding and removing query handlers and processing query
type Interface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}
