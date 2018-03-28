package handlers

import (
	"strings"
	"errors"
)

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")
var ErrQueryInBlacklist = errors.New("query in blacklist")

var ErrAccessToForbiddenTableBlacklist = errors.New("query tries to access forbidden table | blacklist")
var ErrAccessToForbiddenTableWhitelist = errors.New("query tries to access forbidden table | whitelist")

var ErrForbiddenSqlStructureBlacklist = errors.New("query's structure is forbidden | blacklist")
var ErrForbiddenSqlStructureWhitelist = errors.New("query's structure is forbidden | whitelist")


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
		if strings.EqualFold(queryFromRange, query) {

			return true, index
		}
	}
	return false, 0
}