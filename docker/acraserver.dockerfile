FROM golang
RUN apt-get update && apt-get install -y libssl-dev

# install themis
RUN git clone https://github.com/cossacklabs/themis.git /themis
WORKDIR /themis
RUN make install && ldconfig
RUN rm -rf /themis

WORKDIR /go
ENV GOPATH /go

# build acraserver
RUN go get github.com/cossacklabs/acra/...
RUN go build github.com/cossacklabs/acra/cmd/acraserver
RUN go build github.com/cossacklabs/acra/cmd/acra_addzone
RUN go build github.com/cossacklabs/acra/cmd/acra_genpoisonrecord
RUN go build github.com/cossacklabs/acra/cmd/acra_rollback
RUN go build github.com/cossacklabs/acra/cmd/acra_genkeys

VOLUME ["/keys"]
ENTRYPOINT ["acraserver", "--db_host=postgresql_link", "-v", "--keys_dir=/keys"]

# acra server port
EXPOSE 9393
# acra http api port
EXPOSE 9090
