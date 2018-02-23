package firewall


type QueryHandler interface {
	CheckQuery(sqlQuery string) error
}


type AcraFirewall interface {
	HandleQuery(sqlQuery string) error
	AddSpecificHandler(handler QueryHandler)
}



