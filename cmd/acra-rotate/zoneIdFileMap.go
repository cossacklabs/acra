package main

import (
	"encoding/json"
	"errors"
)

// ZoneIdFileMap store dependencies between zone ids and file paths that was encrypted with this zone
type ZoneIdFileMap map[string][]string

// ErrIncorrectConfigFormat is the error when user pass config with incorrect json format
var ErrIncorrectConfigFormat = errors.New("config must have json format {\"zoneId1\": pathToFileStr, \"zoneId2\": [pathToFileStr, pathToFileStr]}")

// ParseConfig parse json config and convert string values to slice of strings to accept both variants of value
func ParseConfig(configData []byte) (ZoneIdFileMap, error) {
	var tempStruct map[string]interface{}
	if err := json.Unmarshal(configData, &tempStruct); err != nil {
		return nil, err
	}

	config := ZoneIdFileMap{}
	for key, value := range tempStruct {
		switch value.(type) {
		case string:
			config[key] = []string{value.(string)}
		case []interface{}:
			config[key] = []string{}
			for _, value := range value.([]interface{}) {
				if strValue, ok := value.(string); ok {
					config[key] = append(config[key], strValue)
				} else {
					return nil, ErrIncorrectConfigFormat
				}
			}
		default:
			return nil, ErrIncorrectConfigFormat
		}
	}
	return config, nil
}
