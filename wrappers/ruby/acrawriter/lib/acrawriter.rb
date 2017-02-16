require 'rubythemis'

SYMMETRIC_KEY_LENGTH = 32

BEGIN_TAG = '""""""""'.b
def create_acrastruct(data, acra_public_key, context=nil)
  if data.nil? or data == ''
    return data
  end
  generator = Themis::SKeyPairGen.new
  private, public = generator.ec
  smessage = Themis::Smessage.new(private.to_s, acra_public_key.to_s)
  random_key = Random.new.bytes(SYMMETRIC_KEY_LENGTH)
  wrapped_random_key = smessage.wrap(random_key.to_s)
  scell = Themis::Scell.new(random_key.to_s, Themis::Scell::SEAL_MODE)
  encrypted_data = scell.encrypt(data, context)
  data_length = Array(encrypted_data.length).pack('Q<')
  BEGIN_TAG + public + wrapped_random_key + data_length + encrypted_data
end
