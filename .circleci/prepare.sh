#!/usr/bin/env bash
mkdir $HOME/$GOPATH_FOLDER

sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get -y install libssl-dev libpq-dev python python-setuptools python3 python3-setuptools python3-pip git rsync psmisc
cd $HOME
git clone https://github.com/cossacklabs/themis
cd themis
sudo make install
cd $HOME
rm -rf themis
for version in $VERSIONS; do
    goroot_folder="go_root_${version}"
    mkdir ${goroot_folder}
    archive=go${version}.linux-amd64.tar.gz
    wget https://storage.googleapis.com/golang/${archive}
    tar -C ${goroot_folder} -xf ${archive};
    rm ${archive}
done

# https://github.com/pypa/pip/issues/5240
python3 -m pip install --user --upgrade pip==9.0.3

pip3 install --user -r $HOME/project/tests/requirements.txt 
# run as separate command due to same dependency 'sqlalchemy' to avoid duplicated requirement and error
# pip3 will use previously installed
pip3 install --user -r $HOME/project/wrappers/python/acrawriter/test-requirements.txt
# install from sources because pip install git+https://github.com/mysql/mysql-connector-python not support recursive submodules
git clone https://github.com/Lagovas/mysql-connector-python
cd mysql-connector-python
sudo python3 setup.py clean build_py install_lib
cd -
rm -rf mysql-connector-python
unset GOROOT
GOPATH=$HOME/$GOPATH_FOLDER go get -u -v golang.org/x/lint/golint
GOPATH=$HOME/$GOPATH_FOLDER go get -u -v github.com/client9/misspell/cmd/misspell
GOPATH=$HOME/$GOPATH_FOLDER go get -u -v github.com/gordonklaus/ineffassign
sudo ldconfig
