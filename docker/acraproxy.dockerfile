FROM golang
RUN apt-get update && apt-get install -y libssl-dev
RUN mkdir /keys

# install themis
RUN git clone https://github.com/cossacklabs/themis.git /themis
WORKDIR /themis
RUN make install && ldconfig
RUN rm -rf /themis

ENV GOPATH /go
WORKDIR /go

RUN mkdir -p src/github.com/cossacklabs/acra
# run from $GOPATH/src/github.com/cossacklabs/acra
COPY . src/github.com/cossacklabs/acra/

# install dependencies
RUN go get github.com/cossacklabs/acra...

# build acraserver
RUN go build github.com/cossacklabs/acra/cmd/acraproxy

COPY .acrakeys .acrakeys
# delete private server keys (with prefixes "_storage" and "_server")
RUN find .acrakeys -name "*_*" -not -name "*_*.pub" | xargs rm
RUN chmod -R 600 .acrakeys && chmod 700 .acrakeys


ENTRYPOINT ["acraproxy"]

CMD ["--acra_host=acraserver_link", "-v", "--client_id=client"]

EXPOSE 9494
EXPOSE 9191
