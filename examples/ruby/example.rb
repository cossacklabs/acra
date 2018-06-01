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

require 'optparse'
require 'pg'
require 'acrawriter'

options = {}
OptionParser.new do |opts|
  opts.on("--dbname=MANDATORY", "Database name") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:dbname] = v
  end
  opts.on("--host=MANDATORY", "Database host") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:host] = v
  end
  opts.on("--port=MANDATORY", "Database port") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:port] = v
  end
  opts.on("--data=MANDATORY", "Data to encrypt") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:data] = v
  end
  opts.on("--print", "Print data from db") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:print] = true
  end
  opts.on("--user=MANDATORY", "Database user") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:user] = v
  end
  opts.on("--password=MANDATORY", "Database password") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:password] = v
  end
  opts.on("--public_key=MANDATORY", "Path to public key that will be used to encrypt data") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:public_key] = v
  end
end.parse!


conn = PG.connect( dbname: options[:dbname], host: options[:host], port: options[:port], user: options[:user], password: options[:password] )
conn.exec('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);')


acra_public = File.read(File.expand_path(options[:public_key]))
acrastruct = create_acrastruct(options[:data], acra_public)
rand_id = rand(100000)
if options[:print]
  conn.exec("SELECT data, raw_data FROM test;") do |result|
    puts "data | raw_data"
    result.each do |row|
      puts "%s | %s " %
               [conn.unescape_bytea(row['data']).to_s, row['raw_data']]
    end
  end
else
  conn.exec_params("INSERT INTO test(id, data, raw_data) VALUES ($1, $2, $3);", [rand_id, conn.escape_bytea(acrastruct), options[:data]])
end

