Gem::Specification.new do |gem|
  gem.name        = 'activerecord_acrawriter'
  gem.version     = '1.0.0'
  gem.date        = '2018-04-23'
  gem.summary     = "Extra type for active record with acrawriter usage"
  gem.description = "Extra type for active record with acrawriter usage"
  gem.authors     = ["Cossack Labs"]
  gem.email       = 'dev@cossacklabs.com'
  gem.files       = ["lib/activerecord_acrawriter.rb"]
  gem.homepage    = 'https://www.cossacklabs.com/'
  gem.license     = 'Apache 2.0'
  gem.add_runtime_dependency 'rubythemis'
  gem.add_runtime_dependency 'acrawriter'
  gem.add_runtime_dependency 'activerecord'
  gem.requirements << 'libthemis, v0.10.0'
end