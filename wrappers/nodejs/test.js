var acra = require('./acra');
var themis = require('jsthemis');


var key_pair = new themis.KeyPair();
var acra_struct = acra.create_acra_struct('andrey', key_pair.public(), 'context')
console.log(acra_struct.length);



