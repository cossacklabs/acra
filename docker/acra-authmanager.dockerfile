# Create internal synonym for previuosly built image
ARG VCS_REF
FROM cossacklabs/acra-build:${VCS_REF} as acra-build

# Build resulting image from scratch
FROM scratch
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
    org.label-schema.name="AcraAuthmanager - HTTP auth key manager" \
    org.label-schema.description="Acra helps you easily secure your databases in distributed, microservice-rich environments" \
    org.label-schema.version=$VERSION \
    org.label-schema.vcs-url=$VCS_URL \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.build-date=$BUILD_DATE \
    com.cossacklabs.product.name="acra" \
    com.cossacklabs.product.version=$VERSION \
    com.cossacklabs.product.vcs-ref=$VCS_REF \
    com.cossacklabs.product.vcs-branch=$VCS_BRANCH \
    com.cossacklabs.product.component="acra-authmanager" \
    com.cossacklabs.docker.container.build-date=$BUILD_DATE \
    com.cossacklabs.docker.container.type="product"
# Copy prepared component's folder from acra-build image
COPY --from=acra-build /container.acra-authmanager/ /
VOLUME ["/auth"]
# Base command
ENTRYPOINT ["/acra-authmanager"]
# Optional arguments
CMD ["--keys_dir=/auth", "--file=/auth/auth.keys"]
