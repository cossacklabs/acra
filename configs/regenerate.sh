#!/usr/bin/env bash
go run ./cmd/acra-server/*.go --dumpconfig
go run ./cmd/acra-connector/*.go --dumpconfig
go run ./cmd/acra_addzone/*.go --dumpconfig
go run ./cmd/acra_configui/*.go --dumpconfig
go run ./cmd/acra_rollback/*.go --dumpconfig
go run ./cmd/acra_genkeys/*.go --dumpconfig
go run ./cmd/acra_genpoisonrecord/*.go --dumpconfig