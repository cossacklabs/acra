Gem::Specification.new do |s|
  s.name        = 'acrawriter'
  s.version     = '1.0.0'
  s.date        = '2016-10-10'
  s.summary     = "Wrapper for acra"
  s.description = "Wrapper for acra"
  s.authors     = ["Cossack Labs"]
  s.email       = 'dev@cossacklabs.com'
  s.files       = ["lib/acrawriter.rb"]
  s.homepage    = 'http://cossacklabs.com/'
  s.license     = 'Apache 2.0'
  s.add_runtime_dependency 'rubythemis'
  s.requirements << 'libthemis, v0.9.3'
end