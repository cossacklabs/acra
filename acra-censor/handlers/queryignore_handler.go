package handlers

type QueryIgnoreHandler struct {
	ignoredQueries map[string]bool
}

func NewQueryIgnoreHandler() *QueryIgnoreHandler {
	handler := &QueryIgnoreHandler{}
	handler.ignoredQueries = make(map[string]bool)
	return handler
}

func (handler *QueryIgnoreHandler) CheckQuery(query string) (bool, error) {
	if handler.ignoredQueries[query]{
		//do not continue query handling
		return false, nil
	}
	return true, nil
}

func (handler *QueryIgnoreHandler) Reset() {
	handler.ignoredQueries = nil
}

func (handler *QueryIgnoreHandler) Release() {
	handler.Reset()
}

func (handler *QueryIgnoreHandler) Priority() int {
	return 1
}

func (handler *QueryIgnoreHandler) AddQueries(queries []string){
	for _, query := range queries{
		handler.ignoredQueries[query] = true
	}
}

func (handler *QueryIgnoreHandler) RemoveQueries(queries []string){
	for _, query := range queries{
		delete(handler.ignoredQueries, query)
	}
}