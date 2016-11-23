require 'json'
require "base64"
require 'pg'
require 'acra'

# output from ./acra_addzone. you should assign your values
zone_data = JSON.parse('{"id":"ZXCfelcOOnfYWkVphBn","public_key":"VUVDMgAAAC1YtTViA+VtaV0qh/OB7Rr3h0U04iQ0pTfPTh9gur62nerv4fsx"}')

conn = PG.connect( dbname: 'acra', host: '127.0.0.1', port: '9494', user: 'postgres', password: 'postgres' )
conn.exec('CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY, zone bytea, data BYTEA, raw_data TEXT);')

zone_public = Base64.decode64(zone_data["public_key"])
zone_id = zone_data["id"]
some_data = (0...8).map { (65 + rand(26)).chr }.join
acrastruct = create_acra_struct(some_data, zone_public, zone_id)

rand_id = rand(100000)
conn.exec_params("INSERT INTO test2(id, zone, data, raw_data) VALUES ($1, $2, $3, $4);", [rand_id, conn.escape_bytea(zone_id), conn.escape_bytea(acrastruct), some_data])

conn.exec("SELECT zone, data, raw_data FROM test2;") do |result|
  puts "zone | data | raw_data"
  result.each do |row|
    puts "%s | %s | %s " %
      [conn.unescape_bytea(row['zone']).to_s, conn.unescape_bytea(row['data']).to_s, row['raw_data']]
  end
end