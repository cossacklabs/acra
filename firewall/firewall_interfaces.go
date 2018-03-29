package firewall


type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) error
	Reset()
}


type FirewallInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
}