# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "websocker/version"

Gem::Specification.new do |s|
  s.name        = "websocker"
  s.version     = Websocker::VERSION
  s.authors     = ["Lawrence Mcalpin"]
  s.email       = ["lmcalpin+turntable_api@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{Library for communicating with Websocket servers.}
  s.description = %q{A simple implementation of a Websocket client.}

  s.rubyforge_project = "websocker"

  s.files         = Dir.glob("{lib}/**/*")
  s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  #s.add_development_dependency "rspec", ">=2.7"
end
