# Create internal synonym for previuosly built image
ARG DOCKER_REGISTRY_PATH
ARG VCS_REF
FROM cossacklabs/acra-server:latest

VOLUME ["/keys"]
EXPOSE 9090 9393

COPY configs/acra-encryptor.yaml /acra-encryptor.yaml

# Base command
ENTRYPOINT ["/acra-server"]
# Optional arguments
CMD ["-v", "--keys_dir=/keys"]
