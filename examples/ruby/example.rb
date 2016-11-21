require 'pg'
require 'acra'


conn = PG.connect( dbname: 'acra', host: '127.0.0.1', port: '9494', user: 'postgres', password: 'postgres' )
conn.exec('CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);')


acra_public = File.read(File.expand_path("~/.ssession/client_server.pub"))
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