#!/bin/bash

home=$(pwd)
versions="1.2.2 1.3 1.3.1 1.3.2 1.3.3 1.4 1.4.1 1.4.2 1.4.3 1.5 1.5.1 1.5.2 1.5.3 1.5.4 1.6 1.6.1 1.6.2 1.6.3 1.6.4 1.7 1.7.1 1.7.2 1.7.3 1.7.4 1.7.5 1.8"
for version in $versions; do mkdir go_root_$version; cd go_root_$version; wget https://storage.googleapis.com/golang/go$version.linux-amd64.tar.gz; tar xf go$version.linux-amd64.tar.gz; cd -; done
for version in $versions; do mkdir -p go_path_$version/src/github.com/cossacklabs/themis/gothemis; mkdir -p go_path_$version/src/github.com/cossacklabs/acra; rsync -auv $home/themis/gothemis/ go_path_$version/src/github.com/cossacklabs/themis/gothemis; rsync -auv $home/acra go_path_$version/src/github.com/cossacklabs; done
for version in $versions; do GOROOT=$home/go_root_$version/go PATH=$GOROOT/bin/:$PATH GOPATH=$home/go_path_$version go get github.com/cossacklabs/acra/...; done
for version in $versions; do GOROOT=$home/go_root_$version/go PATH=$GOROOT/bin/:$PATH GOPATH=$home/go_path_$version go test -v github.com/cossacklabs/acra/...; done
