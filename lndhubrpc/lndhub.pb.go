// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.9
// source: lndhubrpc/lndhub.proto

package lndhubrpc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SubsribeInvoicesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SubsribeInvoicesRequest) Reset() {
	*x = SubsribeInvoicesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_lndhubrpc_lndhub_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubsribeInvoicesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubsribeInvoicesRequest) ProtoMessage() {}

func (x *SubsribeInvoicesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_lndhubrpc_lndhub_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubsribeInvoicesRequest.ProtoReflect.Descriptor instead.
func (*SubsribeInvoicesRequest) Descriptor() ([]byte, []int) {
	return file_lndhubrpc_lndhub_proto_rawDescGZIP(), []int{0}
}

type Invoice struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id                   uint32                   `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Type                 string                   `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	UserId               uint32                   `protobuf:"varint,3,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Amount               uint32                   `protobuf:"varint,4,opt,name=amount,proto3" json:"amount,omitempty"`
	Fee                  uint32                   `protobuf:"varint,5,opt,name=fee,proto3" json:"fee,omitempty"`
	Memo                 string                   `protobuf:"bytes,6,opt,name=memo,proto3" json:"memo,omitempty"`
	DescriptionHash      string                   `protobuf:"bytes,7,opt,name=description_hash,json=descriptionHash,proto3" json:"description_hash,omitempty"`
	PaymentRequest       string                   `protobuf:"bytes,8,opt,name=payment_request,json=paymentRequest,proto3" json:"payment_request,omitempty"`
	DestinationPubkeyHex string                   `protobuf:"bytes,9,opt,name=destination_pubkey_hex,json=destinationPubkeyHex,proto3" json:"destination_pubkey_hex,omitempty"`
	CustomRecords        []*Invoice_CustomRecords `protobuf:"bytes,10,rep,name=custom_records,json=customRecords,proto3" json:"custom_records,omitempty"`
	RHash                string                   `protobuf:"bytes,11,opt,name=r_hash,json=rHash,proto3" json:"r_hash,omitempty"`
	Preimage             string                   `protobuf:"bytes,12,opt,name=preimage,proto3" json:"preimage,omitempty"`
	Keysend              bool                     `protobuf:"varint,13,opt,name=keysend,proto3" json:"keysend,omitempty"`
	State                string                   `protobuf:"bytes,14,opt,name=state,proto3" json:"state,omitempty"`
	CreatedAt            *timestamppb.Timestamp   `protobuf:"bytes,15,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	ExpiresAt            *timestamppb.Timestamp   `protobuf:"bytes,16,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	UpdatedAt            *timestamppb.Timestamp   `protobuf:"bytes,17,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	SettledAt            *timestamppb.Timestamp   `protobuf:"bytes,18,opt,name=settled_at,json=settledAt,proto3" json:"settled_at,omitempty"`
}

func (x *Invoice) Reset() {
	*x = Invoice{}
	if protoimpl.UnsafeEnabled {
		mi := &file_lndhubrpc_lndhub_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Invoice) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Invoice) ProtoMessage() {}

func (x *Invoice) ProtoReflect() protoreflect.Message {
	mi := &file_lndhubrpc_lndhub_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Invoice.ProtoReflect.Descriptor instead.
func (*Invoice) Descriptor() ([]byte, []int) {
	return file_lndhubrpc_lndhub_proto_rawDescGZIP(), []int{1}
}

func (x *Invoice) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Invoice) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Invoice) GetUserId() uint32 {
	if x != nil {
		return x.UserId
	}
	return 0
}

func (x *Invoice) GetAmount() uint32 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *Invoice) GetFee() uint32 {
	if x != nil {
		return x.Fee
	}
	return 0
}

func (x *Invoice) GetMemo() string {
	if x != nil {
		return x.Memo
	}
	return ""
}

func (x *Invoice) GetDescriptionHash() string {
	if x != nil {
		return x.DescriptionHash
	}
	return ""
}

func (x *Invoice) GetPaymentRequest() string {
	if x != nil {
		return x.PaymentRequest
	}
	return ""
}

func (x *Invoice) GetDestinationPubkeyHex() string {
	if x != nil {
		return x.DestinationPubkeyHex
	}
	return ""
}

func (x *Invoice) GetCustomRecords() []*Invoice_CustomRecords {
	if x != nil {
		return x.CustomRecords
	}
	return nil
}

func (x *Invoice) GetRHash() string {
	if x != nil {
		return x.RHash
	}
	return ""
}

func (x *Invoice) GetPreimage() string {
	if x != nil {
		return x.Preimage
	}
	return ""
}

func (x *Invoice) GetKeysend() bool {
	if x != nil {
		return x.Keysend
	}
	return false
}

func (x *Invoice) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *Invoice) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Invoice) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

func (x *Invoice) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Invoice) GetSettledAt() *timestamppb.Timestamp {
	if x != nil {
		return x.SettledAt
	}
	return nil
}

type Invoice_CustomRecords struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Invoice_CustomRecords) Reset() {
	*x = Invoice_CustomRecords{}
	if protoimpl.UnsafeEnabled {
		mi := &file_lndhubrpc_lndhub_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Invoice_CustomRecords) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Invoice_CustomRecords) ProtoMessage() {}

func (x *Invoice_CustomRecords) ProtoReflect() protoreflect.Message {
	mi := &file_lndhubrpc_lndhub_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Invoice_CustomRecords.ProtoReflect.Descriptor instead.
func (*Invoice_CustomRecords) Descriptor() ([]byte, []int) {
	return file_lndhubrpc_lndhub_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Invoice_CustomRecords) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Invoice_CustomRecords) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

var File_lndhubrpc_lndhub_proto protoreflect.FileDescriptor

var file_lndhubrpc_lndhub_proto_rawDesc = []byte{
	0x0a, 0x16, 0x6c, 0x6e, 0x64, 0x68, 0x75, 0x62, 0x72, 0x70, 0x63, 0x2f, 0x6c, 0x6e, 0x64, 0x68,
	0x75, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6c, 0x6e, 0x64, 0x68, 0x75, 0x62,
	0x72, 0x70, 0x63, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x19, 0x0a, 0x17, 0x53, 0x75, 0x62, 0x73, 0x72, 0x69, 0x62, 0x65,
	0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0xdf, 0x05, 0x0a, 0x07, 0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74,
	0x12, 0x10, 0x0a, 0x03, 0x66, 0x65, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x66,
	0x65, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x65, 0x6d, 0x6f, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6d, 0x65, 0x6d, 0x6f, 0x12, 0x29, 0x0a, 0x10, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x61, 0x73,
	0x68, 0x12, 0x27, 0x0a, 0x0f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x70, 0x61, 0x79, 0x6d,
	0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x16, 0x64, 0x65,
	0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x5f, 0x68, 0x65, 0x78, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x14, 0x64, 0x65, 0x73, 0x74,
	0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x48, 0x65, 0x78,
	0x12, 0x47, 0x0a, 0x0e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6c, 0x6e, 0x64, 0x68, 0x75,
	0x62, 0x72, 0x70, 0x63, 0x2e, 0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x2e, 0x43, 0x75, 0x73,
	0x74, 0x6f, 0x6d, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x52, 0x0d, 0x63, 0x75, 0x73, 0x74,
	0x6f, 0x6d, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x15, 0x0a, 0x06, 0x72, 0x5f, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x72, 0x48, 0x61, 0x73, 0x68,
	0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x65, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x0c, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x65, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x6b, 0x65, 0x79, 0x73, 0x65, 0x6e, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x6b,
	0x65, 0x79, 0x73, 0x65, 0x6e, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18,
	0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x39, 0x0a, 0x0a,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x10, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73,
	0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74,
	0x18, 0x11, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a,
	0x0a, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x12, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x73,
	0x65, 0x74, 0x74, 0x6c, 0x65, 0x64, 0x41, 0x74, 0x1a, 0x37, 0x0a, 0x0d, 0x43, 0x75, 0x73, 0x74,
	0x6f, 0x6d, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x32, 0x65, 0x0a, 0x13, 0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x53, 0x75, 0x62, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x4e, 0x0a, 0x10, 0x53, 0x75, 0x62, 0x73,
	0x72, 0x69, 0x62, 0x65, 0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x73, 0x12, 0x22, 0x2e, 0x6c,
	0x6e, 0x64, 0x68, 0x75, 0x62, 0x72, 0x70, 0x63, 0x2e, 0x53, 0x75, 0x62, 0x73, 0x72, 0x69, 0x62,
	0x65, 0x49, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x12, 0x2e, 0x6c, 0x6e, 0x64, 0x68, 0x75, 0x62, 0x72, 0x70, 0x63, 0x2e, 0x49, 0x6e, 0x76,
	0x6f, 0x69, 0x63, 0x65, 0x22, 0x00, 0x30, 0x01, 0x42, 0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x41, 0x6c, 0x62, 0x79, 0x2f, 0x6c,
	0x6e, 0x64, 0x68, 0x75, 0x62, 0x2e, 0x67, 0x6f, 0x2f, 0x6c, 0x6e, 0x64, 0x68, 0x75, 0x62, 0x72,
	0x70, 0x63, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_lndhubrpc_lndhub_proto_rawDescOnce sync.Once
	file_lndhubrpc_lndhub_proto_rawDescData = file_lndhubrpc_lndhub_proto_rawDesc
)

func file_lndhubrpc_lndhub_proto_rawDescGZIP() []byte {
	file_lndhubrpc_lndhub_proto_rawDescOnce.Do(func() {
		file_lndhubrpc_lndhub_proto_rawDescData = protoimpl.X.CompressGZIP(file_lndhubrpc_lndhub_proto_rawDescData)
	})
	return file_lndhubrpc_lndhub_proto_rawDescData
}

var file_lndhubrpc_lndhub_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_lndhubrpc_lndhub_proto_goTypes = []interface{}{
	(*SubsribeInvoicesRequest)(nil), // 0: lndhubrpc.SubsribeInvoicesRequest
	(*Invoice)(nil),                 // 1: lndhubrpc.Invoice
	(*Invoice_CustomRecords)(nil),   // 2: lndhubrpc.Invoice.CustomRecords
	(*timestamppb.Timestamp)(nil),   // 3: google.protobuf.Timestamp
}
var file_lndhubrpc_lndhub_proto_depIdxs = []int32{
	2, // 0: lndhubrpc.Invoice.custom_records:type_name -> lndhubrpc.Invoice.CustomRecords
	3, // 1: lndhubrpc.Invoice.created_at:type_name -> google.protobuf.Timestamp
	3, // 2: lndhubrpc.Invoice.expires_at:type_name -> google.protobuf.Timestamp
	3, // 3: lndhubrpc.Invoice.updated_at:type_name -> google.protobuf.Timestamp
	3, // 4: lndhubrpc.Invoice.settled_at:type_name -> google.protobuf.Timestamp
	0, // 5: lndhubrpc.InvoiceSubscription.SubsribeInvoices:input_type -> lndhubrpc.SubsribeInvoicesRequest
	1, // 6: lndhubrpc.InvoiceSubscription.SubsribeInvoices:output_type -> lndhubrpc.Invoice
	6, // [6:7] is the sub-list for method output_type
	5, // [5:6] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_lndhubrpc_lndhub_proto_init() }
func file_lndhubrpc_lndhub_proto_init() {
	if File_lndhubrpc_lndhub_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_lndhubrpc_lndhub_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubsribeInvoicesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_lndhubrpc_lndhub_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Invoice); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_lndhubrpc_lndhub_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Invoice_CustomRecords); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_lndhubrpc_lndhub_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_lndhubrpc_lndhub_proto_goTypes,
		DependencyIndexes: file_lndhubrpc_lndhub_proto_depIdxs,
		MessageInfos:      file_lndhubrpc_lndhub_proto_msgTypes,
	}.Build()
	File_lndhubrpc_lndhub_proto = out.File
	file_lndhubrpc_lndhub_proto_rawDesc = nil
	file_lndhubrpc_lndhub_proto_goTypes = nil
	file_lndhubrpc_lndhub_proto_depIdxs = nil
}
