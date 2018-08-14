#!/usr/bin/env bash
go run ./cmd/acra-server/*.go --dump_config
go run ./cmd/acra-connector/*.go --dump_config
go run ./cmd/acra-translator/*.go --dump_config
go run ./cmd/acra-addzone/*.go --dump_config
go run ./cmd/acra-webconfig/*.go --dump_config
go run ./cmd/acra-rollback/*.go --dump_config
go run ./cmd/acra-keymaker/*.go --dump_config
go run ./cmd/acra-poisonrecordmaker/*.go --dump_config
go run ./cmd/acra-authmanager/*.go --dump_config
go run ./cmd/acra-rotate/*.go --dump_config
