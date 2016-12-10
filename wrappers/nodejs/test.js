var acra = require('./acrawriter');
var themis = require('jsthemis');


var key_pair = new themis.KeyPair();
var acra_struct = acra.create_acrastruct('andrey', key_pair.public(), 'context')
console.log(acra_struct.length);



