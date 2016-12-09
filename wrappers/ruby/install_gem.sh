#!/usr/bin/env bash
gem uninstall acrawriter
rm acra-1.*
gem build acrawriter.gemspec
gem install ./acrawriter-1.0.0.gem
