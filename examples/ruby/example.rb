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
require 'dbi'
require 'pg'
#require 'dbd/pg/type'
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

if !options[:mysql]
  options[:postgresql] = true
end

driver = "Pg"
if options[:mysql]
  driver = "Mysql"
  #conn = PG.connect( dbname: options[:dbname], host: options[:host], port: options[:port], user: options[:user], password: options[:password] )
end


DBI.connect('DBI:%s:database=%s;host=%s;port=%s;sslmode=disable' % [driver, options[:dbname], options[:host], options[:port]], options[:user], options[:password]) do | db_driver |
  if options[:mysql]
    db_driver.do('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data VARBINARY(1000), raw_data VARCHAR(1000));')
  else
    db_driver.do('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);')
  end

  if options[:print]

    puts "data | raw_data"
    db_driver.select_all('SELECT data, raw_data FROM test;') do | row |
      puts "%s | %s " % [row['data'].to_s, row['raw_data']]
      # if options[:mysql]
      #   puts "%s | %s " % [row['data'].to_s, row['raw_data']]
      # else
      #   puts "%s | %s " % [PGconn.unescape_bytea(row['data']).to_s, row['raw_data']]
      # end
    end

  else
    acra_public = File.read(File.expand_path(options[:public_key]))
    if options[:mysql]
      acrastruct = DBI::Binary.new(create_acrastruct(options[:data], acra_public))
    else
      acrastruct = DBI::DBD::Pg::Type::ByteA.new(create_acrastruct(options[:data], acra_public))
    end


    rand_id = rand(100000)
    p "insert"
    db_driver.do("INSERT INTO test(id, data, raw_data) VALUES (?, ?, ?);", rand_id, acrastruct, options[:data])
    db_driver.commit
  end
end

puts "done"
