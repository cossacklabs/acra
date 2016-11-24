
Gem::Specification.new do |s|
  s.name        = 'acra'
  s.version     = '1.0.1'
  s.date        = '2016-10-10'
  s.summary     = "Wrapper for acra"
  s.description = "Wrapper for acra"
  s.authors     = ["testhandle", "testhandle2"]
  s.email       = 'lagovas@securetechnologies.eu'
  s.files       = ["lib/acra.rb"]
  s.homepage    = 'http://cossacklabs.com/'
  s.license     = 'Apache 2.0'
  s.add_runtime_dependency 'rubythemis'
  s.requirements << 'libthemis, v0.9.3'
end