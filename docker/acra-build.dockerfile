FROM debian:stretch
ARG VERSION
ARG VCS_REF
ARG VCS_BRANCH
ARG BUILD_DATE
LABEL com.cossacklabs.product.name="acra" \
    com.cossacklabs.product.version="$VERSION" \
    com.cossacklabs.product.vcs-ref="$VCS_REF" \
    com.cossacklabs.product.vcs-branch="$VCS_BRANCH" \
    com.cossacklabs.product.component="acraserver" \
    com.cossacklabs.docker.container.build-date="$BUILD_DATE" \
    com.cossacklabs.docker.container.type="build"
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
RUN ["/bin/bash", "-c", \
    "set -o pipefail && \
    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
      bash -s -- --yes --method source --branch $VCS_BRANCH \
      --without-packing --without-clean"]
RUN GO_SRC_FILE="go1.9.3.linux-amd64.tar.gz" && \
    wget --no-verbose --no-check-certificate \
      "https://storage.googleapis.com/golang/${GO_SRC_FILE}" && \
    tar xf "./${GO_SRC_FILE}"
RUN git clone -b $VCS_BRANCH https://github.com/cossacklabs/acra
ENV GOROOT="/root/go" GOPATH="/root/gopath"
ENV PATH="$GOROOT/bin/:$PATH"
ENV GOPATH_ACRA="${GOPATH}/src/github.com/cossacklabs/acra"
RUN mkdir -p "${GOPATH}/src/github.com/cossacklabs/acra" && \
    rsync -au acra/* "${GOPATH_ACRA}/"
RUN mkdir -p "${GOPATH}/src/github.com/cossacklabs/themis/gothemis" && \
    rsync -au themis/gothemis/ \
      "${GOPATH}/src/github.com/cossacklabs/themis/gothemis"
RUN go get -d -t -v -x github.com/cossacklabs/acra/...
RUN go get -v -x github.com/cossacklabs/acra/...
COPY collect_dependencies.sh .
RUN chmod +x ./collect_dependencies.sh
RUN for component in server proxy; do \
      ./collect_dependencies.sh \
        "${GOPATH}/bin/acra${component}" "/container.acra${component}" && \
      cp "${GOPATH}/bin/acra${component}" "/container.acra${component}/"; \
    done
