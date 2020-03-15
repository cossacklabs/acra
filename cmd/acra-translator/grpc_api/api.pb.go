// Code generated by protoc-gen-go.
// source: cmd/acra-translator/grpc_api/api.proto
// DO NOT EDIT!

/*
Package grpc_api is a generated protocol buffer package.

It is generated from these files:
	cmd/acra-translator/grpc_api/api.proto

It has these top-level messages:
	DecryptRequest
	DecryptResponse
	EncryptRequest
	EncryptResponse
*/
package grpc_api

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type DecryptRequest struct {
	ClientId   []byte `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ZoneId     []byte `protobuf:"bytes,2,opt,name=zone_id,json=zoneId,proto3" json:"zone_id,omitempty"`
	Acrastruct []byte `protobuf:"bytes,3,opt,name=acrastruct,proto3" json:"acrastruct,omitempty"`
}

func (m *DecryptRequest) Reset()                    { *m = DecryptRequest{} }
func (m *DecryptRequest) String() string            { return proto.CompactTextString(m) }
func (*DecryptRequest) ProtoMessage()               {}
func (*DecryptRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type DecryptResponse struct {
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *DecryptResponse) Reset()                    { *m = DecryptResponse{} }
func (m *DecryptResponse) String() string            { return proto.CompactTextString(m) }
func (*DecryptResponse) ProtoMessage()               {}
func (*DecryptResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type EncryptRequest struct {
	ClientId []byte `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	ZoneId   []byte `protobuf:"bytes,2,opt,name=zone_id,json=zoneId,proto3" json:"zone_id,omitempty"`
	Data     []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *EncryptRequest) Reset()                    { *m = EncryptRequest{} }
func (m *EncryptRequest) String() string            { return proto.CompactTextString(m) }
func (*EncryptRequest) ProtoMessage()               {}
func (*EncryptRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type EncryptResponse struct {
	Acrastruct []byte `protobuf:"bytes,1,opt,name=acrastruct,proto3" json:"acrastruct,omitempty"`
}

func (m *EncryptResponse) Reset()                    { *m = EncryptResponse{} }
func (m *EncryptResponse) String() string            { return proto.CompactTextString(m) }
func (*EncryptResponse) ProtoMessage()               {}
func (*EncryptResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func init() {
	proto.RegisterType((*DecryptRequest)(nil), "grpc_api.DecryptRequest")
	proto.RegisterType((*DecryptResponse)(nil), "grpc_api.DecryptResponse")
	proto.RegisterType((*EncryptRequest)(nil), "grpc_api.EncryptRequest")
	proto.RegisterType((*EncryptResponse)(nil), "grpc_api.EncryptResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion3

// Client API for Reader service

type ReaderClient interface {
	Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error)
}

type readerClient struct {
	cc *grpc.ClientConn
}

func NewReaderClient(cc *grpc.ClientConn) ReaderClient {
	return &readerClient{cc}
}

func (c *readerClient) Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error) {
	out := new(DecryptResponse)
	err := grpc.Invoke(ctx, "/grpc_api.Reader/Decrypt", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Reader service

type ReaderServer interface {
	Decrypt(context.Context, *DecryptRequest) (*DecryptResponse, error)
}

func RegisterReaderServer(s *grpc.Server, srv ReaderServer) {
	s.RegisterService(&_Reader_serviceDesc, srv)
}

func _Reader_Decrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReaderServer).Decrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc_api.Reader/Decrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReaderServer).Decrypt(ctx, req.(*DecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Reader_serviceDesc = grpc.ServiceDesc{
	ServiceName: "grpc_api.Reader",
	HandlerType: (*ReaderServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Decrypt",
			Handler:    _Reader_Decrypt_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

// Client API for Writer service

type WriterClient interface {
	Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error)
}

type writerClient struct {
	cc *grpc.ClientConn
}

func NewWriterClient(cc *grpc.ClientConn) WriterClient {
	return &writerClient{cc}
}

func (c *writerClient) Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error) {
	out := new(EncryptResponse)
	err := grpc.Invoke(ctx, "/grpc_api.Writer/Encrypt", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Writer service

type WriterServer interface {
	Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error)
}

func RegisterWriterServer(s *grpc.Server, srv WriterServer) {
	s.RegisterService(&_Writer_serviceDesc, srv)
}

func _Writer_Encrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WriterServer).Encrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpc_api.Writer/Encrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WriterServer).Encrypt(ctx, req.(*EncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Writer_serviceDesc = grpc.ServiceDesc{
	ServiceName: "grpc_api.Writer",
	HandlerType: (*WriterServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Encrypt",
			Handler:    _Writer_Encrypt_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

func init() { proto.RegisterFile("cmd/acra-translator/grpc_api/api.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 254 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xac, 0x91, 0x4d, 0x4b, 0xc4, 0x30,
	0x10, 0x86, 0xb7, 0xae, 0x74, 0xd7, 0x41, 0x76, 0x21, 0x17, 0xab, 0x82, 0x48, 0x40, 0xf1, 0x62,
	0x8b, 0xfa, 0x07, 0x3c, 0xe8, 0x41, 0x8f, 0xbd, 0x08, 0x5e, 0x96, 0x98, 0x8c, 0x52, 0x58, 0x93,
	0x38, 0x99, 0x3d, 0xe8, 0xaf, 0x77, 0xfb, 0xb5, 0xa4, 0xc5, 0xa3, 0x87, 0x42, 0x33, 0x2f, 0x3c,
	0xef, 0x93, 0x09, 0x5c, 0xea, 0x4f, 0x53, 0x28, 0x4d, 0xea, 0x9a, 0x49, 0xd9, 0xb0, 0x56, 0xec,
	0xa8, 0xf8, 0x20, 0xaf, 0x57, 0xca, 0x57, 0xc5, 0xf6, 0xcb, 0x3d, 0x39, 0x76, 0x62, 0xde, 0xcf,
	0xe4, 0x3b, 0x2c, 0x1e, 0x50, 0xd3, 0xb7, 0xe7, 0x12, 0xbf, 0x36, 0x18, 0x58, 0x9c, 0xc2, 0x81,
	0x5e, 0x57, 0x68, 0x79, 0x55, 0x99, 0x2c, 0x39, 0x4f, 0xae, 0x0e, 0xcb, 0x79, 0x3b, 0x78, 0x32,
	0xe2, 0x08, 0x66, 0x3f, 0xce, 0x62, 0x1d, 0xed, 0x35, 0x51, 0x5a, 0x1f, 0xb7, 0xc1, 0x19, 0x40,
	0xdd, 0x1b, 0x98, 0x36, 0x9a, 0xb3, 0x69, 0x93, 0x45, 0x13, 0x79, 0x01, 0xcb, 0x5d, 0x4f, 0xf0,
	0xce, 0x06, 0x14, 0x02, 0xf6, 0x8d, 0x62, 0xd5, 0x75, 0x34, 0xff, 0xf2, 0x15, 0x16, 0x8f, 0xf6,
	0x1f, 0x74, 0x7a, 0xf6, 0x34, 0x62, 0xdf, 0xc0, 0x72, 0xc7, 0xee, 0x14, 0x86, 0xd6, 0xc9, 0xd8,
	0xfa, 0xf6, 0x19, 0xd2, 0x12, 0x95, 0x41, 0x12, 0xf7, 0x30, 0xeb, 0xfc, 0x45, 0x96, 0xf7, 0xdb,
	0xcb, 0x87, 0xab, 0x3b, 0x39, 0xfe, 0x23, 0x69, 0x9b, 0xe4, 0xa4, 0x66, 0xbd, 0x50, 0xc5, 0x2d,
	0xab, 0x13, 0x89, 0x59, 0xc3, 0x7b, 0xc7, 0xac, 0x91, 0xb5, 0x9c, 0xbc, 0xa5, 0xcd, 0x33, 0xde,
	0xfd, 0x06, 0x00, 0x00, 0xff, 0xff, 0x22, 0x8e, 0xf8, 0x4b, 0xf0, 0x01, 0x00, 0x00,
}
