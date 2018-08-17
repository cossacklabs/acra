Gem::Specification.new do |gem|
  gem.name        = 'acrawriter'
  gem.version     = '1.0.2'
  gem.date        = '2018-08-14'
  gem.summary     = "AcraWriter library for Python: encrypts data into AcraStructs, allowing Acra to decrypt it"
  gem.description = "Acra helps you easily secure your databases in distributed, microservice-rich environments. It allows you to selectively encrypt sensitive records with strong multi-layer cryptography, detect potential intrusions and SQL injections and cryptographically compartmentalise data stored in large sharded schemes. "
  gem.authors     = ["Cossack Labs"]
  gem.email       = 'dev@cossacklabs.com'
  gem.files       = ["lib/acrawriter.rb"]
  gem.test_files  = ["test/test_acrawriter.rb"]
  gem.homepage    = 'https://github.com/cossacklabs/acra'
  gem.license     = 'Apache 2.0'
  gem.add_runtime_dependency 'rubythemis', '~> 0.9.5'
  gem.requirements << 'libthemis, v0.10.0'
end