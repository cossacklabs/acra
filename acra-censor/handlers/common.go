/*
Copyright 2018, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package handlers

import (
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
	"strings"
)

// ParsePatterns replace placeholders with our values which used to match patterns and parse them with sqlparser
func ParsePatterns(patterns []string) ([][]sqlparser.SQLNode, error) {
	placeholders := []string{SelectConfigPlaceholder, ColumnConfigPlaceholder, WhereConfigPlaceholder, ValueConfigPlaceholder, ListOfValuesConfigPlaceholder, SubqueryConfigPlaceholder}
	replacers := []string{SelectConfigPlaceholderReplacer, ColumnConfigPlaceholderReplacer, WhereConfigPlaceholderReplacer, ValueConfigPlaceholderReplacer, ListOfValuesConfigPlaceholderReplacer, SubqueryConfigPlaceholderReplacer}
	patternValue := ""
	var outputPatterns [][]sqlparser.SQLNode
	for _, pattern := range patterns {
		patternValue = pattern
		for index, placeholder := range placeholders {
			patternValue = strings.Replace(patternValue, placeholder, replacers[index], -1)
		}
		statement, err := sqlparser.Parse(patternValue)
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).WithField("pattern", patternValue).WithError(err).Errorln("Can't add specified pattern in blacklist handler")
			return nil, ErrPatternSyntaxError
		}
		var newPatternNodes []sqlparser.SQLNode
		sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
			newPatternNodes = append(newPatternNodes, node)
			return true, nil
		}, statement)
		outputPatterns = append(outputPatterns, newPatternNodes)
	}
	return outputPatterns, nil

}
