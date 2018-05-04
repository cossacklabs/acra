#!/usr/bin/env bash
go run ./cmd/acra-server/*.go --dumpconfig
go run ./cmd/acra-connector/*.go --dumpconfig
go run ./cmd/acra-addzone/*.go --dumpconfig
go run ./cmd/acra-webconfig/*.go --dumpconfig
go run ./cmd/acra-rollback/*.go --dumpconfig
go run ./cmd/acra-keymaker/*.go --dumpconfig
go run ./cmd/acra-poisonrecordmaker/*.go --dumpconfig