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

// Package acracensor represents separate firewall module for Acra. AcraCensor handles each query that
// gets through AcraServer. You can setup the whitelist and the blacklist separately or simultaneously.
// The order of priority for the lists is defined by their order in the configuration file.
// Priority of work for one of the lists is the following: queries, followed by tables, followed by rules.
//
// https://github.com/cossacklabs/acra/wiki/AcraCensor
package acracensor

// QueryHandlerInterface describes what actions are available for queries.
type QueryHandlerInterface interface {
	CheckQuery(sqlQuery string) (bool, error) //1st return arg specifies whether continue verification or not, 2nd specifies whether query is forbidden
	Release()
}

// AcraCensorInterface describes main AcraCensor methods: adding and removing query handlersand processing query
type AcraCensorInterface interface {
	HandleQuery(sqlQuery string) error
	AddHandler(handler QueryHandlerInterface)
	RemoveHandler(handler QueryHandlerInterface)
	ReleaseAll()
}
