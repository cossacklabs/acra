package firewall


type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) error

	Refresh()

	AddQueries(queries []string)
	RemoveQueries(queries []string)

	AddTables(tables []string)
	RemoveTables(tables []string)

	AddRules(rules []string)
	RemoveRules(rules []string)

	GetActiveQueries() []string
	GetActiveTables() []string
	GetActiveRules() []string
}


type FirewallInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
}