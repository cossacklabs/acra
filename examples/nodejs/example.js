//
// Copyright (c) 2015 Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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


var acra_key = fs.readFileSync('.acrakeys/client_storage.pub');

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