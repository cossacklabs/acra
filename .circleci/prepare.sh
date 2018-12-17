#!/usr/bin/env bash
sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get -y install libssl-dev python python-setuptools python3 python3-setuptools python3-pip git rsync psmisc
cd $HOME && git clone https://github.com/cossacklabs/themis && cd themis && sudo make install
cd $HOME && for version in $VERSIONS; do mkdir go_root_$version; cd go_root_$version; wget https://storage.googleapis.com/golang/go$version.linux-amd64.tar.gz; tar xf go$version.linux-amd64.tar.gz; cd -; done
mkdir $HOME/$GOPATH_FOLDER
cd $HOME && mkdir -p $HOME/$GOPATH_FOLDER/src/github.com/cossacklabs/themis; mkdir -p $HOME/$GOPATH_FOLDER/src/github.com/cossacklabs/acra; ln -s $HOME/themis/gothemis $HOME/$GOPATH_FOLDER/src/github.com/cossacklabs/themis/gothemis; cp -r $HOME/project/* $HOME/$GOPATH_FOLDER/src/github.com/cossacklabs/acra/
cd $HOME && GOPATH=$HOME/$GOPATH_FOLDER go get -d github.com/cossacklabs/acra/...
pip3 install -r $HOME/project/tests/requirements.txt -r $HOME/project/wrappers/python/acrawriter/test-requirements.txt
# install from sources because pip install git+https://github.com/mysql/mysql-connector-python not support recursive submodules
git clone https://github.com/Lagovas/mysql-connector-python; cd mysql-connector-python; sudo python3 setup.py clean build_py install_lib
cd $HOME && GOPATH=$HOME/$GOPATH_FOLDER go get -u -v golang.org/x/lint/golint
sudo ldconfig
