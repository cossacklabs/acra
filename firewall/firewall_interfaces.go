package firewall


type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) error

	AddQueries(queries []string)
	RemoveQueries(queries []string)

	AddTables(tables []string)
	RemoveTables(tables []string)
}


type FirewallInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
}