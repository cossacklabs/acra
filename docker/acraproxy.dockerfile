ARG VCS_REF
FROM cossacklabs/acra-build:${VCS_REF} as acra-build

FROM scratch
ARG VERSION
ARG VCS_URL
ARG VCS_REF
ARG VCS_BRANCH
ARG BUILD_DATE
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.vendor="Cossack Labs" \
    org.label-schema.url="https://cossacklabs.com" \
    org.label-schema.name="Acra server" \
    org.label-schema.description="Acra helps you easily secure your databases in distributed, microservice-rich environments" \
    org.label-schema.version=$VERSION \
    org.label-schema.vcs-url=$VCS_URL \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.build-date=$BUILD_DATE \
    com.cossacklabs.product.name="acra" \
    com.cossacklabs.product.version=$VERSION \
    com.cossacklabs.product.vcs-ref=$VCS_REF \
    com.cossacklabs.product.vcs-branch=$VCS_BRANCH \
    com.cossacklabs.product.component="acraproxy" \
    com.cossacklabs.docker.container.build-date=$BUILD_DATE \
    com.cossacklabs.docker.container.type="product"
COPY --from=acra-build /container.acraproxy/ /
VOLUME ["/keys"]
EXPOSE 9191 9494
ENTRYPOINT ["/acraproxy"]
CMD ["--acra_host=acraserver_link", "-v", "--keys_dir=/keys"]
