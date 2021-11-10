FROM debian:bullseye

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
    python3 python3-setuptools python3-pip \
    rsync \
    sudo \
    rustc \
    wget

WORKDIR /root

# Install libthemis
RUN set -o pipefail && \
    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
        bash -s -- --yes

# Include helpful scripts
RUN mkdir /image.scripts
COPY docker/_scripts/acra-build/install_go.sh /image.scripts/
COPY docker/_scripts/acra-build/install_go.csums /image.scripts/
RUN chmod +x /image.scripts/*.sh

# Install Go
RUN GO_VERSIONS='1.15.2 1.16.9 1.17.3' \
    GO_TARBALL_CLEAN=1 \
    /image.scripts/install_go.sh

ENV GOROOT="/usr/local/lib/go/latest" GOPATH="/home/user/gopath" GO111MODULE="auto"

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
ENV PATH="$GOROOT/bin:/home/user/gopath/bin:/home/user/.local/bin:$PATH"

# Install some Go linters
RUN go get -u -v golang.org/x/lint/golint && \
    go get -u -v github.com/client9/misspell/cmd/misspell && \
    go get -u -v github.com/gordonklaus/ineffassign

# Install Python tests dependencies

COPY tests/requirements.txt /home/user/python_tests_requirements.txt
COPY wrappers/python/acrawriter/test-requirements.txt /home/user/python_acrawriter_tests_requirements.txt

RUN pip3 install --user -r /home/user/python_tests_requirements.txt && \
    # run as separate command due to same dependency 'sqlalchemy' to avoid duplicated requirement and error \
    pip3 install --user -r $HOME/python_acrawriter_tests_requirements.txt && \
    # install from sources because pip install git+https://... not support recursive submodules \
    git clone https://github.com/Lagovas/mysql-connector-python && \
    cd mysql-connector-python && \
    python3 setup.py clean build_py && \
    sudo python3 setup.py install_lib && \
    cd - && \
    sudo rm -rf mysql-connector-python
