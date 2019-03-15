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

  def serialize(value)
    return '' if value.to_s.empty?

    key = Base64.decode64(Rails.application.secrets.acra_public_key)
    acrastruct = create_acrastruct(value.b, key)

    case ActiveRecord::Base.connection.adapter_name
    when 'PostgreSQL'
      return ActiveRecord::Base.connection.escape_bytea(acrastruct)
    when 'Mysql2'
      return acrastruct.b
    end

    raise 'Do not know how to operate with adapter ' +
        ActiveRecord::Base.connection.adapter_name
  end

  private

    def cast_value(value)
      return '' if value.to_s.empty?

      case ActiveRecord::Base.connection.adapter_name
      when 'PostgreSQL'
        return [value[2..-1]].pack('H*') if value.start_with?('\x')
        return value.to_s
      when 'Mysql2'
        return value.to_s
      end

      raise 'Do not know how to operate with adapter ' +
        ActiveRecord::Base.connection.adapter_name
    end
end
