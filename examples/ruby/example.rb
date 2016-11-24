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
require 'pg'
require 'acra'


conn = PG.connect( dbname: 'acra', host: '127.0.0.1', port: '9494', user: 'postgres', password: 'postgres' )
conn.exec('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);')


acra_public = File.read(File.expand_path(".acrakeys/client_server.pub"))
some_data = (0...8).map { (65 + rand(26)).chr }.join
acrastruct = create_acra_struct(some_data, acra_public)
rand_id = rand(100000)
conn.exec_params("INSERT INTO test(id, data, raw_data) VALUES ($1, $2, $3);", [rand_id, conn.escape_bytea(acrastruct), some_data])

conn.exec("SELECT data, raw_data FROM test;") do |result|
  puts "data | raw_data"
  result.each do |row|
    puts "%s | %s " %
      [conn.unescape_bytea(row['data']).to_s, row['raw_data']]
  end
end