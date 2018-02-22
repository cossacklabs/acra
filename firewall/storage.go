package firewall

import (
	"os"
	"bufio"
	"fmt"
)

type storageHandlingCallback func (sqlQuery string, blacklistPath string, whitelistPath string) error


func specificQueryHandler(sqlQuery string, blacklistPath string, whitelistPath string) error {

	//Add every query to whitelist if it is not presented there
	queries, err := readLines(whitelistPath)
	if err != nil{
		return nil
	}

	queries = append(queries, sqlQuery)
	removeDuplicates(&queries)

	err = writeLines(queries, whitelistPath)
	if err != nil {
		return nil
	}

	return nil
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}


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
