FROM golang
RUN apt-get update && apt-get install -y libssl-dev

# install themis
RUN git clone https://github.com/cossacklabs/themis.git /themis
WORKDIR /themis
RUN make install && ldconfig
RUN rm -rf /themis

ENV GOPATH /go

RUN mkdir -p /go/src/github.com/cossacklabs/acra
# run from $GOPATH/src/github.com/cossacklabs/acra
COPY . /go/src/github.com/cossacklabs/acra/

# install dependencies
RUN go get github.com/cossacklabs/acra...

# build acraserver
RUN go build github.com/cossacklabs/acra/cmd/acraserver
RUN go build github.com/cossacklabs/acra/cmd/acra_addzone

COPY .acrakeys .acrakeys
RUN chmod -R 600 .acrakeys && chmod 700 .acrakeys


ENTRYPOINT ["acraserver"]
CMD ["--db_host=postgresql_link", "-v"]

# acra server port
EXPOSE 9393
# acra http api port
EXPOSE 9090
