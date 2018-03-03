package handlers

func removeDuplicates(input []string) []string {

	keys := make(map[string] bool)
	var result []string
	for _, entry := range input{
		if _, value := keys[entry]; !value {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result

}

func contains(queries []string, query string) (bool, int) {

	for index, queryFromRange := range queries {
		if queryFromRange == query {

			return true, index
		}
	}
	return false, 0
}