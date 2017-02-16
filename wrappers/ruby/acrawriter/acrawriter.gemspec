Gem::Specification.new do |gem|
  gem.name        = 'acrawriter'
  gem.version     = '1.0.0'
  gem.date        = '2016-10-10'
  gem.summary     = "Wrapper for acra"
  gem.description = "Wrapper for acra"
  gem.authors     = ["Cossack Labs"]
  gem.email       = 'dev@cossacklabs.com'
  gem.files       = ["lib/acrawriter.rb"]
  gem.test_files  = ["test/test_acrawriter.rb"]
  gem.homepage    = 'http://cossacklabs.com/'
  gem.license     = 'Apache 2.0'
  gem.add_runtime_dependency 'rubythemis'
  gem.requirements << 'libthemis, v0.9.3'
end