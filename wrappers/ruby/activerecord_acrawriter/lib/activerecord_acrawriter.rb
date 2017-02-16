require 'active_record'
require 'acrawriter'

class AcraType < ActiveRecord::Type::String
  def type_cast_for_database(value)
    # scell can't encrypt null or empty objects
    if value.nil? or value == ''
      super
    else
      key = Base64.decode64(Rails.application.secrets.acra_public_key)
      ActiveRecord::Base.connection.escape_bytea(create_acrastruct(value.b, key))
    end
  end
  def type_cast_from_database(value)
    ActiveRecord::Base.connection.unescape_bytea(value)
  end
end