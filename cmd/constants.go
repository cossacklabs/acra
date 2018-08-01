/*
Copyright 2016, Cossack Labs Limited

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

// Package cmd contains shared settings/constants among most of Acra component utilities.
package cmd

// Acra component constants: default port, host, names, path.
const (
	DEFAULT_ACRACONNECTOR_PORT                = 9494
	DEFAULT_ACRACONNECTOR_API_PORT            = 9191
	DEFAULT_ACRACONNECTOR_CONNECTION_PROTOCOL = "tcp"
	DEFAULT_ACRACONNECTOR_HOST                = "127.0.0.1"
	DEFAULT_ACRA_HOST                         = "0.0.0.0"
	DEFAULT_ACRASERVER_PORT                   = 9393
	DEFAULT_ACRASERVER_API_PORT               = 9090
	DEFAULT_ACRA_AUTH_PATH                    = "configs/auth.keys"
	DEFAULT_ACRA_CONNECTION_PROTOCOL          = "tcp"
	DEFAULT_ACRAWEBCONFIG_HOST                = "127.0.0.1"
	DEFAULT_ACRAWEBCONFIG_PORT                = 8000
	DEFAULT_ACRAWEBCONFIG_STATIC              = "cmd/acra-webconfig/static"
	DEFAULT_ACRAWEBCONFIG_AUTH_MODE           = "auth_on"
	ACRAWEBCONFIG_AUTH_ARGON2_LENGTH          = 32
	ACRAWEBCONFIG_AUTH_ARGON2_MEMORY          = 8 * 1024
	ACRAWEBCONFIG_AUTH_ARGON2_TIME            = 3
	ACRAWEBCONFIG_AUTH_ARGON2_THREADS         = 2
	DEFAULT_ACRATRANSLATOR_HTTP_HOST          = "0.0.0.0"
	DEFAULT_ACRATRANSLATOR_HTTP_PORT          = 9595
	DEFAULT_ACRATRANSLATOR_GRPC_HOST          = "0.0.0.0"
	DEFAULT_ACRATRANSLATOR_GRPC_PORT          = 9696
)
