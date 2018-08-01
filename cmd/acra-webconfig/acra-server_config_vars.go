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

// Package main is entry point for AcraWebConfig service.AcraWebConfig is a lightweight HTTP web server for managing
// AcraServer's certain configuration options. AcraWebConfig uses HTTP API requests to get data from AcraServer
// and to change its settings. To provide additional security, AcraWebConfig uses basic authentication.
// Users/passwords are stored in an encrypted file and are managed by AcraAuthmanager utility.
//
// https://github.com/cossacklabs/acra/wiki/AcraWebConfig
package main

// AcraServerConfig describes AcraServer configuration that can be changed from AcraWebconfig page.
var AcraServerConfig = `config:
  -
    name: db_host
    title: Host for destination Postgres
    value_type: string
    input_type: text
  -
    name: db_port
    title: Port for destination Postgres
    value_type: int8
    input_type: number
  -
    name: incoming_connection_api_port
    title: Port for AcraServer's HTTP API
    value_type: int8
    input_type: number
  -
    name: debug
    title: Turn on debug logging
    value_type: bool
    input_type: radio
    values: [true, false]
    labels: [Yes, No]
  -
    name: poison_run_script_file
    title: Execute script on detecting poison record
    value_type: string
    input_type: text
  -
    name: poison_shutdown_enable
    title: Stop on detecting poison record
    value_type: bool
    values: [true, false]
    labels: [Yes, No]
    input_type: radio
  -
    name: zonemode_enable
    title: Turn on zone mode
    value_type: bool
    values: [true, false]
    labels: [Yes, No]
    input_type: radio
`
