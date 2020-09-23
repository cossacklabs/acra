FROM debian:buster

SHELL ["/bin/bash", "-c"]

# Install dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
    apt-transport-https \
    build-essential \
    ca-certificates \
    curl \
    default-mysql-client \
    git \
    gnupg \
    libpq-dev \
    libssl-dev \
    openssl \
    postgresql-client \
    psmisc \
    python python-setuptools \
    python3 python3-setuptools python3-pip \
    rsync \
    sudo \
    wget

WORKDIR /root

# Install libthemis
RUN set -o pipefail && \
    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
        bash -s -- --yes

# Include helpful scripts
RUN mkdir /image.scripts
COPY docker/_scripts/acra-build/install_go.sh /image.scripts/
RUN chmod +x /image.scripts/*.sh

# Install Go
RUN GO_PREFIX_DIR=/usr/lib/go/1.13.15 \
    GO_VERSION=1.13.15 \
    GO_TARBALL_DIGEST=01cc3ddf6273900eba3e2bf311238828b7168b822bb57a9ccab4d7aa2acd6028 \
    GO_TARBALL_CLEAN=1 \
    /image.scripts/install_go.sh

RUN GO_PREFIX_DIR=/usr/lib/go/1.14.9 \
    GO_VERSION=1.14.9 \
    GO_TARBALL_DIGEST=f0d26ff572c72c9823ae752d3c81819a81a60c753201f51f89637482531c110a \
    GO_TARBALL_CLEAN=1 \
    /image.scripts/install_go.sh

RUN GO_PREFIX_DIR=/usr/lib/go/1.15.2 \
    GO_VERSION=1.15.2 \
    GO_TARBALL_DIGEST=b49fda1ca29a1946d6bb2a5a6982cf07ccd2aba849289508ee0f9918f6bb4552 \
    GO_TARBALL_CLEAN=1 \
    /image.scripts/install_go.sh

ENV GOROOT="/usr/lib/go/1.15.2/go" GOPATH="/home/user/gopath" GO111MODULE="auto"
# if you need Go, put `export PATH=$GOROOT/bin:$PATH` in you scripts
# if you need a different Go version, set GOROOT to another /usr/lib/go/*/go before setting PATH

# Create the user and allow using `sudo` without password
RUN useradd -m user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-user

USER user
WORKDIR /home/user

#
# from now we'll run stuff as `user`, not as `root`
#

# `go get` installs binaries into $GOPATH/bin, thus into ~/gopath/bin
# `pip` installs binaries into ~/.local/bin
ENV PATH="/home/user/gopath/bin:/home/user/.local/bin:$PATH"

# Install some Go linters
RUN PATH=$GOROOT/bin:$PATH go get -u -v golang.org/x/lint/golint
RUN PATH=$GOROOT/bin:$PATH go get -u -v github.com/client9/misspell/cmd/misspell
RUN PATH=$GOROOT/bin:$PATH go get -u -v github.com/gordonklaus/ineffassign

# Install Python tests dependencies

COPY tests/requirements.txt /home/user/python_tests_requirements.txt
COPY wrappers/python/acrawriter/test-requirements.txt /home/user/python_acrawriter_tests_requirements.txt

RUN pip3 install --user -r /home/user/python_tests_requirements.txt 
# run as separate command due to same dependency 'sqlalchemy' to avoid duplicated requirement and error
RUN pip3 install --user -r $HOME/python_acrawriter_tests_requirements.txt 
# install from sources because pip install git+https://github.com/mysql/mysql-connector-python not support recursive submodules
RUN git clone https://github.com/Lagovas/mysql-connector-python && \
    cd mysql-connector-python && \
    python3 setup.py clean build_py && \
    sudo python3 setup.py install_lib && \
    cd - && \
    sudo rm -rf mysql-connector-python
