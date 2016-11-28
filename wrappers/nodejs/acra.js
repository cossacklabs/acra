var themis = require('jsthemis');
var int64 = require('int64-buffer').Uint64LE


module.exports = {

    create_acra_struct: function(data, acra_public_key, context){
	var data_buffer = Buffer.isBuffer(data)?data:(new Buffer(data));
	var context_buffer = Buffer.isBuffer(context)?context:(new Buffer(context));
	var random_keypair = new themis.KeyPair();
	var sm = new themis.SecureMessage(random_keypair.private(), acra_public_key);
	var random_key = require('crypto').randomBytes(32);
	var wrapped_random_key = sm.encrypt(random_key);
	var sc = new themis.SecureCellSeal(random_key);
	var encrypted_data = context?sc.encrypt(data_buffer, context_buffer):sc.encrypt(data_buffer);
	var begin_tag = new Buffer([133,32,251]);
	var encrypted_data_length = new int64(encrypted_data.length).toBuffer();
	console.log(encrypted_data_length);
	return Buffer.concat([begin_tag, random_keypair.public(), wrapped_random_key, encrypted_data_length, encrypted_data]);
    }

};

