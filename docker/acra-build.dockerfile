FROM debian:stretch
# Product version
ARG VERSION
# Hash of the commit
ARG VCS_REF
# Repository branch
ARG VCS_BRANCH
# Date of the build
ARG BUILD_DATE
# Include metadata
LABEL com.cossacklabs.product.name="acra" \
    com.cossacklabs.product.version="$VERSION" \
    com.cossacklabs.product.vcs-ref="$VCS_REF" \
    com.cossacklabs.product.vcs-branch="$VCS_BRANCH" \
    com.cossacklabs.product.component="acra-build" \
    com.cossacklabs.docker.container.build-date="$BUILD_DATE" \
    com.cossacklabs.docker.container.type="build"
# Install dependencies
RUN apt-get update && apt-get -y install \
    apt-transport-https \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    libssl-dev \
    openssl \
    rsync \
    wget
WORKDIR /root
# Install libthemis, keep sources for later use
RUN ["/bin/bash", "-c", \
    "set -o pipefail && \
    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
        bash -s -- --yes --method source --branch $VCS_BRANCH \
        --without-packing --without-clean"]
# Install golang and set environment variables
RUN GO_SRC_FILE="go1.10.3.linux-amd64.tar.gz" && \
    wget --no-verbose --no-check-certificate \
        "https://storage.googleapis.com/golang/${GO_SRC_FILE}" && \
    tar xf "./${GO_SRC_FILE}"
ENV GOROOT="/root/go" GOPATH="/root/gopath"
ENV PATH="$GOROOT/bin/:$PATH"
ENV GOPATH_ACRA="${GOPATH}/src/github.com/cossacklabs/acra"
COPY ./ "${GOPATH}/src/github.com/cossacklabs/acra/"
RUN mkdir -p "${GOPATH}/src/github.com/cossacklabs/themis/gothemis" && \
    rsync -au themis/gothemis/ \
        "${GOPATH}/src/github.com/cossacklabs/themis/gothemis"
# Fetch and build dependencies
RUN go get -d -t -v -x github.com/cossacklabs/acra/...
# Build previously fetched acra
RUN go get -v -x github.com/cossacklabs/acra/...
# Include scripts for finding dependencies and prepare resulting directories
COPY docker/_scripts/acra-build/add_component.sh .
RUN chmod +x ./add_component.sh
COPY docker/_scripts/acra-build/collect_dependencies.sh .
RUN chmod +x ./collect_dependencies.sh
# Copy each product and its dependencies to resulting directories
RUN for component in server connector translator keymaker webconfig authmanager; do \
        if [ "$component" = "server" ]; then \
            ./add_component.sh "poisonrecordmaker" "$component"; \
            ./add_component.sh "rollback" "$component"; \
        fi; \
        if [ "$component" = "translator" ]; then \
            ./add_component.sh "poisonrecordmaker" "$component"; \
        fi; \
        ./add_component.sh "$component" "$component"; \
    done
# Copy static resources for acra-webconfig
RUN cp -r "${GOPATH}/src/github.com/cossacklabs/acra/cmd/acra-webconfig/static" \
    "/container.acra-webconfig/"
