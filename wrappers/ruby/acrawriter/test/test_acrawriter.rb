require 'minitest/autorun'
require 'rubythemis'
require 'acrawriter'

class TestAcrawriter < Minitest::Test
  def test_create_acrastruct
    generator = Themis::SKeyPairGen.new
    private, public = generator.ec
    create_acrastruct("some data", public, context=nil)
  end
end