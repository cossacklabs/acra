package benchmark

import (
	"bufio"
	"fmt"
	"os"
)

const MAX_DATA_DISTRIBUTION = 25000

func LoadDataMaterial(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

func SaveUniqueInput(uniqueInput []string) error {
	file, err := os.OpenFile("current_unique_input", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range uniqueInput {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}
