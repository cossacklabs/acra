FROM golang
RUN apt-get update && apt-get install -y libssl-dev

# install themis
RUN git clone https://github.com/cossacklabs/themis.git /themis
WORKDIR /themis
RUN make install && ldconfig
RUN rm -rf /themis

ENV GOPATH /go
WORKDIR /go

# build acraproxy
RUN go get github.com/cossacklabs/acra/...
RUN go build github.com/cossacklabs/acra/cmd/acraproxy

VOLUME ["/keys"]
ENTRYPOINT ["acraproxy", "--acra_host=acraserver_link", "-v", "--keys_dir=/keys"]

EXPOSE 9494
EXPOSE 9191
