# Install grpc dependencies
```
# from https://github.com/grpc/grpc-go
go get -u github.com/golang/protobuf/{proto,protoc-gen-go}
go get -u google.golang.org/grpc
```
To recompile proto file run from root of acra repository:
```
protoc --go_out=plugins=grpc:. cmd/acra-reader/api/api.proto
```
