package handlers

// QueryIgnoreHandler shows handler structure
type QueryIgnoreHandler struct {
	ignoredQueries map[string]bool
}

// NewQueryIgnoreHandler creates new ignore handler
func NewQueryIgnoreHandler() *QueryIgnoreHandler {
	handler := &QueryIgnoreHandler{}
	handler.ignoredQueries = make(map[string]bool)
	return handler
}

// CheckQuery checks each query, returns false if query handling should be ignored.
func (handler *QueryIgnoreHandler) CheckQuery(query string) (bool, error) {
	if handler.ignoredQueries[query] {
		//do not continue query handling
		return false, nil
	}
	return true, nil
}

// Reset ignored patterns
func (handler *QueryIgnoreHandler) Reset() {
	handler.ignoredQueries = make(map[string]bool)
}

// Release / reset ignored patterns
func (handler *QueryIgnoreHandler) Release() {
	handler.Reset()
}

// AddQueries adds queries to the list that should be ignored
func (handler *QueryIgnoreHandler) AddQueries(queries []string) {
	for _, query := range queries {
		handler.ignoredQueries[query] = true
	}
}

// RemoveQueries removes queries from the list that should be whitelisted
func (handler *QueryIgnoreHandler) RemoveQueries(queries []string) {
	for _, query := range queries {
		delete(handler.ignoredQueries, query)
	}
}
