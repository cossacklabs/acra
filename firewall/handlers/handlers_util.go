package handlers

func removeDuplicates(xs *[]string) {

	found := make(map[string]bool)
	j := 0

	for i, x := range *xs {
		if !found[x] {
			found[x] = true
			(*xs)[j] = (*xs)[i]
			j++
		}
	}
	*xs = (*xs)[:j]
}

func contains(queries []string, query string) (bool, int) {

	for index, queryFromRange := range queries {
		if queryFromRange == query {

			return true, index
		}
	}
	return false, 0
}