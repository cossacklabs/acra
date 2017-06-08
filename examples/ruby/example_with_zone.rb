# Copyright 2016, Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
require 'json'
require "base64"
require 'pg'
require 'acrawriter'

# output from ./acra_addzone. you should assign your values
zone_data = JSON.parse('{"id":"DDDDDDDDhydxgNoxWYxYRZzf","public_key":"VUVDMgAAAC11q5/TAmIAS42yyuNISRCsbl56D/yBH0iSZ9nmVfhdaOP0mwSH"}')

conn = PG.connect( dbname: 'acra', host: '127.0.0.1', port: '9494', user: 'postgres', password: 'postgres' )
conn.exec('CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY, zone bytea, data BYTEA, raw_data TEXT);')

zone_public = Base64.decode64(zone_data["public_key"])
zone_id = zone_data["id"]
some_data = (0...8).map { (65 + rand(26)).chr }.join
acrastruct = create_acrastruct(some_data, zone_public, zone_id)

rand_id = rand(100000)
conn.exec_params("INSERT INTO test2(id, zone, data, raw_data) VALUES ($1, $2, $3, $4);", [rand_id, conn.escape_bytea(zone_id), conn.escape_bytea(acrastruct), some_data])

conn.exec("SELECT zone, data, raw_data FROM test2;") do |result|
  puts "zone | data | raw_data"
  result.each do |row|
    puts "%s | %s | %s " %
      [conn.unescape_bytea(row['zone']).to_s, conn.unescape_bytea(row['data']).to_s, row['raw_data']]
  end
end
