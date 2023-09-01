FROM debian:bookworm

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
    python3 python3-setuptools python3-pip python3.11-venv \
    rsync \
    sudo \
    rustc \
    wget

WORKDIR /root

# Install MariaDB Connector/C for mariadb python driver
RUN wget https://r.mariadb.com/downloads/mariadb_repo_setup && \
    echo "935944a2ab2b2a48a47f68711b43ad2d698c97f1c3a7d074b34058060c2ad21b  mariadb_repo_setup" \
        | sha256sum -c - && chmod +x mariadb_repo_setup

# Configure the CS package repository using the mariadb_repo_setup utility:
RUN sudo /root/mariadb_repo_setup --mariadb-server-version="mariadb-11.2"

RUN apt -y install libmariadb3 libmariadb-dev

# Install libthemis:
# RUN set -o pipefail && \
#    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
#        bash -s -- --yes
RUN cd /root \
    && git clone --depth 1 -b stable https://github.com/cossacklabs/themis
RUN cd /root/themis \
    && make \
    && make install

# Include helpful scripts
RUN mkdir /image.scripts
COPY docker/_scripts/acra-build/install_go.sh /image.scripts/
COPY docker/_scripts/acra-build/install_go.csums /image.scripts/
COPY go.mod /image.scripts/
RUN chmod +x /image.scripts/*.sh

# Install Go

RUN GO_VERSIONS='1.21.0' \
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
RUN go install golang.org/x/lint/golint@v0.0.0-20210508222113-6edffad5e616 && \
    go install github.com/client9/misspell/cmd/misspell@v0.3.4 && \
    go install golang.org/x/tools/cmd/goyacc@v0.11.0 && \
    go install github.com/swaggo/swag/cmd/swag@v1.16.1 && \
    go install github.com/gordonklaus/ineffassign@v0.0.0-20230610083614-0e73809eb601

# download dependencies to avoid next downloads in tests
RUN cp /image.scripts/go.mod . && go mod download && rm go.mod go.sum

# Install Python tests dependencies

COPY tests/requirements.txt /home/user/python_tests_requirements.txt
COPY wrappers/python/acrawriter/test-requirements.txt /home/user/python_acrawriter_tests_requirements.txt

RUN python3 -m venv ./venv

ENV VIRTUAL_ENV /home/user/venv
ENV PATH /home/user/venv/bin:$PATH

RUN pip3 install -r /home/user/python_tests_requirements.txt && \
    # run as separate command due to same dependency 'sqlalchemy' to avoid duplicated requirement and error \
    pip3 install -r $HOME/python_acrawriter_tests_requirements.txt && \
    # install from sources because pip install git+https://... not support recursive submodules \
    git clone https://github.com/Lagovas/mysql-connector-python && \
    cd mysql-connector-python && \
    python3 setup.py clean build_py && \
    sudo python3 setup.py install_lib && \
    cd - && \
    sudo rm -rf mysql-connector-python
