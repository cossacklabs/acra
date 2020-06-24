# Create internal synonym for previuosly built image
ARG DOCKER_REGISTRY_PATH
ARG VCS_REF
FROM ${DOCKER_REGISTRY_PATH}/acra-build:${VCS_REF} as acra-build

# Build resulting image from scratch
FROM scratch
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

# Include metadata, additionally use label-schema namespace
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.vendor="Cossack Labs" \
    org.label-schema.url="https://cossacklabs.com" \
    org.label-schema.name="AcraServer CE" \
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
    com.cossacklabs.product.component="acra-server" \
    com.cossacklabs.docker.container.build-date="$BUILD_DATE" \
    com.cossacklabs.docker.container.type="product"

# Copy prepared component's folder from acra-build image
COPY --from=acra-build /container.acra-server/ /

VOLUME ["/keys"]
EXPOSE 9090 9393

# Base command
ENTRYPOINT ["/acra-server"]
# Optional arguments
CMD ["-v", "--keys_dir=/keys"]
