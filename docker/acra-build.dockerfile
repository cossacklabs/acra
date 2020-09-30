FROM debian:buster

# Application name
ARG APP_NAME
# Product version
ARG VERSION
# Link to the product repository
ARG VCS_URL
# Hash of the commit
ARG VCS_REF
# Repository branch
ARG VCS_BRANCH
# Date of the build
ARG BUILD_DATE

# Include metadata
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.vendor="Cossack Labs" \
    org.label-schema.url="https://cossacklabs.com" \
    org.label-schema.name="Acra CE build image" \
    org.label-schema.description="Acra helps you easily secure your databases in distributed, microservice-rich environments" \
    org.label-schema.version="$VERSION" \
    org.label-schema.vcs-url="$VCS_URL" \
    org.label-schema.vcs-ref="$VCS_REF" \
    org.label-schema.build-date="$BUILD_DATE" \
    com.cossacklabs.vendor.name="Cossack Labs Limited" \
    com.cossacklabs.vendor.url="https://www.cossacklabs.com" \
    com.cossacklabs.vendor.email="dev@cossacklabs.com" \
    com.cossacklabs.product.name="$APP_NAME" \
    com.cossacklabs.product.version="$VERSION" \
    com.cossacklabs.product.vcs-ref="$VCS_REF" \
    com.cossacklabs.product.vcs-branch="$VCS_BRANCH" \
    com.cossacklabs.product.component="$APP_NAME" \
    com.cossacklabs.docker.container.build-date="$BUILD_DATE" \
    com.cossacklabs.docker.container.type="build"

SHELL ["/bin/bash", "-c"]

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

# Install libthemis
RUN set -o pipefail && \
    curl -sSL https://pkgs.cossacklabs.com/scripts/libthemis_install.sh | \
        bash -s -- --yes

# Include scripts
RUN mkdir /image.scripts
COPY docker/_scripts/acra-build/add_component.sh /image.scripts/
COPY docker/_scripts/acra-build/collect_dependencies.sh /image.scripts/
COPY docker/_scripts/acra-build/install_go.sh /image.scripts/
COPY docker/_scripts/acra-build/install_go.csums /image.scripts/
RUN chmod +x /image.scripts/*.sh

# Install Go
RUN GO_TARBALL_CLEAN=1 /image.scripts/install_go.sh
ENV GOROOT="/usr/local/lib/go/latest" GOPATH="/root/gopath" GO111MODULE="auto"
ENV PATH="$PATH:/usr/local/lib/go/latest/bin"

# Copy Acra sources
ENV PATH_ACRA="/acra"
COPY ./ "${PATH_ACRA}/"
# Fetch all dependencies and build all binaries in acra
RUN cd "${PATH_ACRA}" && go install ./cmd/...

# Copy each product and its dependencies to resulting directories
RUN for component in authmanager connector keymaker server tools translator webconfig; do \
        ADD_COMPONENTS=(); \
        if [ "$component" == 'tools' ]; then \
            ADD_COMPONENTS+=('addzone' 'authmanager' 'keymaker' 'poisonrecordmaker' 'rollback' 'rotate'); \
        else \
            ADD_COMPONENTS+=("$component"); \
        fi; \
        if [ "$component" = 'server' ]; then \
            ADD_COMPONENTS+=('poisonrecordmaker' 'rollback'); \
        fi; \
        if [ "$component" = 'translator' ]; then \
            ADD_COMPONENTS+=('poisonrecordmaker'); \
        fi; \
        for c in ${ADD_COMPONENTS[@]}; do \
            /image.scripts/add_component.sh "$c" "$component"; \
        done; \
    done
# Copy static resources for acra-webconfig
RUN cp -r "${PATH_ACRA}/cmd/acra-webconfig/static" \
    "/container.acra-webconfig/"
