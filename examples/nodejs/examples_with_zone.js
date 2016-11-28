var acra = require('acra');
var pg = require('pg');
var request = require('sync-request');

var res = request('GET', 'http://127.0.0.1:9191/getNewZone');
var zone = JSON.parse(res.getBody().toString('utf8'));
console.log(zone);

var raw_data = 'Test Message';

var config = {
  user: 'andrey', 
  database: 'acra', 
  password: 'andrey',
  host: 'localhost',
  port: 9494, 
  max: 10, 
  idleTimeoutMillis: 30000,
};

var pool = new pg.Pool(config);
pool.connect(function(err, client, done) {
  if(err) {
    return console.error('error fetching client from pool', err);
  }
  client.query('CREATE TABLE IF NOT EXISTS testjs(id SERIAL PRIMARY KEY, zone BYTEA, data BYTEA, raw_data TEXT)', [], function(err, res) {
    done();
    if(err) {
      return console.error('error running query', err);
    }
  });
  client.query('insert into testjs (zone, data, raw_data) values ($1, $2, $3)', [zone.id, acra.create_acra_struct(raw_data, new Buffer(zone.public_key, 'base64'), zone.id), raw_data], function(err, res) {
    done();
    if(err) {
      return console.error('error running query', err);
    }
  });

  client.query('select zone, data, raw_data from testjs', [], function(err, res) {
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