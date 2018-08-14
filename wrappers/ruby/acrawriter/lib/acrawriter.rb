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
  private.clear
  random_key = Random.new.bytes(SYMMETRIC_KEY_LENGTH)
  wrapped_random_key = smessage.wrap(random_key.to_s)
  scell = Themis::Scell.new(random_key.to_s, Themis::Scell::SEAL_MODE)
  random_key.clear
  encrypted_data = scell.encrypt(data, context)
  data_length = Array(encrypted_data.length).pack('Q<')
  BEGIN_TAG + public + wrapped_random_key + data_length + encrypted_data
end
