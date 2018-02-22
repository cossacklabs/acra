package firewall


type AcraFirewall interface {
	ProcessQuery(sqlQuery string) error
	GetStoredQueries() []string
}
