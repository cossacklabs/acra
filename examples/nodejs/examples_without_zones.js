var acra = require('acrawriter');
var pg = require('pg');
var fs = require('fs');

var raw_data = 'Test Message';

var config = {
  user: 'postgres', 
  database: 'acra', 
  password: 'postgres',
  host: 'localhost',
  port: 9494, 
  max: 10, 
  idleTimeoutMillis: 30000,
};


var acra_key = fs.readFileSync('client_storage.pub');

var pool = new pg.Pool(config);
pool.connect(function(err, client, done) {
  if(err) {
    return console.error('error fetching client from pool', err);
  }
  client.query('CREATE TABLE IF NOT EXISTS testjs(id SERIAL PRIMARY KEY, data BYTEA, raw_data TEXT)', [], function(err, res) {
    done();
    if(err) {
      return console.error('error running query', err);
    }
  });
  client.query('insert into testjs (data, raw_data) values ($1, $2)', [acra.create_acra_struct(raw_data, acra_key, ""), raw_data], function(err, res) {
    done();
    if(err) {
      return console.error('error running query', err);
    }
  });

  client.query('select data, raw_data from testjs', [], function(err, res) {
    done();
    if(err) {
      return console.error('error running query', err);
    }
    for(i=0;i<res.rows.length;i++){
        console.log(res.rows[i].zone.toString('utf8'));
        console.log(res.rows[i].data.toString('utf8'));
        console.log(res.rows[i].raw_data.toString('utf8'));
        console.log(" ");
    }
  });
  done();
});

pool.on('error', function (err, client) {
  console.error('idle client error', err.message, err.stack)
})