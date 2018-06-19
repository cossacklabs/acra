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
require 'json'
require "base64"
require 'pg'
require 'dbi'
require 'acrawriter'
require 'net/http'

AcraConnectorAddress = 'http://127.0.0.1:9191'

def get_zone
  res = Net::HTTP.get_response(URI('%s/getNewZone' % AcraConnectorAddress))
  data = res.body if res.is_a?(Net::HTTPSuccess)
  json_data = JSON.parse(data)
  return {:zone_id=>json_data['id'], :public_key=>Base64.decode64(json_data['public_key'])}
end

options = {}
OptionParser.new do |opts|
  opts.on("--db_name=MANDATORY", "Database name") do |v|
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
  opts.on("--db_user=MANDATORY", "Database user") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:user] = v
  end
  opts.on("--db_password=MANDATORY", "Database password") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:password] = v
  end
  opts.on("--zone_id=MANDATORY", "Zone id") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:zone_id] = v
  end
  opts.on("--mysql", "Use mysql driver") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:mysql] = true
  end
  opts.on("--postgresql", "Use postgresql driver (default)") do |v|
    if !v
      raise OptionParser::MissingArgument
    end
    options[:postgresql] = true
  end
end.parse!


if options[:mysql]
  db_driver = DBI.connect('DBI:Mysql:database=%s;host=%s;port=%s' % [ options[:dbname], options[:host], options[:port]], options[:user], options[:password])
else
  db_driver = PG.connect( dbname: options[:dbname], host: options[:host], port: options[:port], user: options[:user], password: options[:password] )
end


if options[:mysql]
  db_driver.do('CREATE TABLE IF NOT EXISTS test_example_with_zone(id INTEGER PRIMARY KEY, zone VARBINARY(1000), data VARBINARY(1000), raw_data VARCHAR(1000));')
else
  db_driver.exec_params('CREATE TABLE IF NOT EXISTS test_example_with_zone(id INTEGER PRIMARY KEY, zone bytea, data BYTEA, raw_data TEXT);')
end

if options[:print]
  puts "zone | data | raw_data"
  if options[:mysql]
    db_driver.select_all('SELECT ?, data, raw_data FROM test_example_with_zone;', options[:zone_id]) do | row |
      puts "%s | %s | %s " % [row[0], row['data'].to_s, row['raw_data']]
    end
  else
    db_driver.exec("SELECT $1::bytea as zone, data, raw_data FROM test_example_with_zone;", [db_driver.escape_bytea(options[:zone_id])]) do |result|
      result.each do |row|
        puts "%s | %s | %s " % [db_driver.unescape_bytea(row['zone']).to_s, db_driver.unescape_bytea(row['data']).to_s, row['raw_data']]
      end
    end
  end
else
  zone_data = get_zone()
  zone_public = zone_data[:public_key]
  zone_id = zone_data[:zone_id]
  acrastruct = create_acrastruct(options[:data], zone_public, zone_id)
  rand_id = rand(100000)
  if options[:mysql]
    acrastruct = DBI::Binary.new(acrastruct)
    db_driver.do("INSERT INTO test_example_with_zone(id, zone, data, raw_data) VALUES (?, ?, ?, ?);", rand_id, zone_id, acrastruct, options[:data])
    db_driver.commit
  else
    db_driver.exec_params("INSERT INTO test_example_with_zone(id, zone, data, raw_data) VALUES ($1, $2, $3, $4);", [rand_id, db_driver.escape_bytea(zone_id), db_driver.escape_bytea(acrastruct), options[:data]])
  end

  puts "zone_id=%s" % zone_id
end

puts "done"