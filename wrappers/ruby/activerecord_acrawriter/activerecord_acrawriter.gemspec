Gem::Specification.new do |gem|
  gem.name        = 'activerecord_acrawriter'
  gem.version     = '1.0.3'
  gem.date        = '2019-03-19'
  gem.summary     = "Extra type for active record with AcraWriter usage"
  gem.description = "Acra helps you easily secure your databases in distributed, microservice-rich environments. It allows you to selectively encrypt sensitive records with strong multi-layer cryptography, detect potential intrusions and SQL injections and cryptographically compartmentalise data stored in large sharded schemes. "
  gem.authors     = ["Cossack Labs"]
  gem.email       = 'dev@cossacklabs.com'
  gem.files       = ["lib/activerecord_acrawriter.rb"]
  gem.homepage    = 'https://github.com/cossacklabs/acra'
  gem.license     = 'Apache 2.0'
  gem.add_runtime_dependency 'acrawriter', '~> 1.0.3'
  gem.add_runtime_dependency 'activerecord', '>= 0'
end
