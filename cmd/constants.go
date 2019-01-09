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

package cmd

// Acra component constants: default port, host, names, path.
const (
	DefaultAcraConnectorPort               = 9494
	DefaultAcraConnectorAPIPort            = 9191
	DefaultAcraConnectorConnectionProtocol = "tcp"
	DefaultAcraConnectorHost               = "127.0.0.1"
	DefaultAcraServerHost                  = "0.0.0.0"
	DefaultAcraServerPort                  = 9393
	DefaultAcraServerAPIPort               = 9090
	DefaultAcraServerAuthPath              = "configs/auth.keys"
	DefaultAcraServerConnectionProtocol    = "tcp"
	DefaultWebConfigHost                   = "127.0.0.1"
	DefaultWebConfigPort                   = 8000
	DefaultWebConfigStatic                 = "cmd/acra-webconfig/static"
	DefaultWebConfigAuthMode               = "auth_on"
	DefaultWebConfigAuthArgon2Length       = 32
	DefaultWebConfigAuthArgon2Memory       = 8 * 1024
	DefaultWebConfigAuthArgon2Time         = 3
	DefaultWebConfigAuthArgon2Threads      = 2
	DefaultAcraTranslatorGRPCHost          = "0.0.0.0"
	DefaultAcraTranslatorGRPCPort          = 9696
)
