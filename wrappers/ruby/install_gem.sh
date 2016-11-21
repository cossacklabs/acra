#!/usr/bin/env bash
gem uninstall acra
rm acra-1.*
gem build acra.gemspec
gem install ./acra-1.0.1.gem
