package main

var AcraServerCofig = `config:
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
    name: commands_port
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
    name: poisonscript
    title: Execute script on detecting poison record
    value_type: string
    input_type: text
  -
    name: poisonshutdown
    title: Stop on detecting poison record
    value_type: bool
    values: [true, false]
    labels: [Yes, No]
    input_type: radio
  -
    name: zonemode
    title: Turn on zone mode
    value_type: bool
    values: [true, false]
    labels: [Yes, No]
    input_type: radio
`
