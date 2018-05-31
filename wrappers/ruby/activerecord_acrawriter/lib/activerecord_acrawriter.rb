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

require 'active_record'
require 'acrawriter'

class AcraType < ActiveRecord::Type::String
  def cast(value)
    # scell can't encrypt null or empty objects
    if value.nil? or value == ''
      super
    else
      key = Base64.decode64(Rails.application.secrets.acra_public_key)
      ActiveRecord::Base.connection.escape_bytea(create_acrastruct(value.b, key))
    end
  end

  def deserialize(value)
    # override to avoid call cast method
    value
  end
end