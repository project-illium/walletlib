// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.12.4
// source: models.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SpendNote struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address         string           `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Commitment      []byte           `protobuf:"bytes,2,opt,name=commitment,proto3" json:"commitment,omitempty"`
	KeyIndex        uint32           `protobuf:"varint,3,opt,name=key_index,json=keyIndex,proto3" json:"key_index,omitempty"`
	ScriptHash      []byte           `protobuf:"bytes,4,opt,name=scriptHash,proto3" json:"scriptHash,omitempty"`
	Amount          uint64           `protobuf:"varint,5,opt,name=amount,proto3" json:"amount,omitempty"`
	Asset_ID        []byte           `protobuf:"bytes,6,opt,name=asset_ID,json=assetID,proto3" json:"asset_ID,omitempty"`
	State           []byte           `protobuf:"bytes,7,opt,name=state,proto3" json:"state,omitempty"`
	Salt            []byte           `protobuf:"bytes,8,opt,name=salt,proto3" json:"salt,omitempty"`
	AccIndex        uint64           `protobuf:"varint,9,opt,name=acc_index,json=accIndex,proto3" json:"acc_index,omitempty"`
	WatchOnly       bool             `protobuf:"varint,10,opt,name=watch_only,json=watchOnly,proto3" json:"watch_only,omitempty"`
	UnlockingScript *UnlockingScript `protobuf:"bytes,11,opt,name=unlocking_script,json=unlockingScript,proto3" json:"unlocking_script,omitempty"`
}

func (x *SpendNote) Reset() {
	*x = SpendNote{}
	if protoimpl.UnsafeEnabled {
		mi := &file_models_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SpendNote) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SpendNote) ProtoMessage() {}

func (x *SpendNote) ProtoReflect() protoreflect.Message {
	mi := &file_models_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SpendNote.ProtoReflect.Descriptor instead.
func (*SpendNote) Descriptor() ([]byte, []int) {
	return file_models_proto_rawDescGZIP(), []int{0}
}

func (x *SpendNote) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *SpendNote) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

func (x *SpendNote) GetKeyIndex() uint32 {
	if x != nil {
		return x.KeyIndex
	}
	return 0
}

func (x *SpendNote) GetScriptHash() []byte {
	if x != nil {
		return x.ScriptHash
	}
	return nil
}

func (x *SpendNote) GetAmount() uint64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *SpendNote) GetAsset_ID() []byte {
	if x != nil {
		return x.Asset_ID
	}
	return nil
}

func (x *SpendNote) GetState() []byte {
	if x != nil {
		return x.State
	}
	return nil
}

func (x *SpendNote) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

func (x *SpendNote) GetAccIndex() uint64 {
	if x != nil {
		return x.AccIndex
	}
	return 0
}

func (x *SpendNote) GetWatchOnly() bool {
	if x != nil {
		return x.WatchOnly
	}
	return false
}

func (x *SpendNote) GetUnlockingScript() *UnlockingScript {
	if x != nil {
		return x.UnlockingScript
	}
	return nil
}

type WalletTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Txid   []byte `protobuf:"bytes,1,opt,name=txid,proto3" json:"txid,omitempty"`
	AmtIn  uint64 `protobuf:"varint,2,opt,name=amtIn,proto3" json:"amtIn,omitempty"`
	AmtOut uint64 `protobuf:"varint,3,opt,name=amtOut,proto3" json:"amtOut,omitempty"`
}

func (x *WalletTransaction) Reset() {
	*x = WalletTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_models_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WalletTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WalletTransaction) ProtoMessage() {}

func (x *WalletTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_models_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WalletTransaction.ProtoReflect.Descriptor instead.
func (*WalletTransaction) Descriptor() ([]byte, []int) {
	return file_models_proto_rawDescGZIP(), []int{1}
}

func (x *WalletTransaction) GetTxid() []byte {
	if x != nil {
		return x.Txid
	}
	return nil
}

func (x *WalletTransaction) GetAmtIn() uint64 {
	if x != nil {
		return x.AmtIn
	}
	return 0
}

func (x *WalletTransaction) GetAmtOut() uint64 {
	if x != nil {
		return x.AmtOut
	}
	return 0
}

type AddrInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr            string           `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
	UnlockingScript *UnlockingScript `protobuf:"bytes,2,opt,name=unlocking_script,json=unlockingScript,proto3" json:"unlocking_script,omitempty"`
	ViewPrivKey     []byte           `protobuf:"bytes,3,opt,name=view_priv_key,json=viewPrivKey,proto3" json:"view_priv_key,omitempty"`
	KeyIndex        uint32           `protobuf:"varint,4,opt,name=key_index,json=keyIndex,proto3" json:"key_index,omitempty"`
	WatchOnly       bool             `protobuf:"varint,5,opt,name=watch_only,json=watchOnly,proto3" json:"watch_only,omitempty"`
}

func (x *AddrInfo) Reset() {
	*x = AddrInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_models_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddrInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddrInfo) ProtoMessage() {}

func (x *AddrInfo) ProtoReflect() protoreflect.Message {
	mi := &file_models_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddrInfo.ProtoReflect.Descriptor instead.
func (*AddrInfo) Descriptor() ([]byte, []int) {
	return file_models_proto_rawDescGZIP(), []int{2}
}

func (x *AddrInfo) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

func (x *AddrInfo) GetUnlockingScript() *UnlockingScript {
	if x != nil {
		return x.UnlockingScript
	}
	return nil
}

func (x *AddrInfo) GetViewPrivKey() []byte {
	if x != nil {
		return x.ViewPrivKey
	}
	return nil
}

func (x *AddrInfo) GetKeyIndex() uint32 {
	if x != nil {
		return x.KeyIndex
	}
	return 0
}

func (x *AddrInfo) GetWatchOnly() bool {
	if x != nil {
		return x.WatchOnly
	}
	return false
}

type UnlockingScript struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScriptCommitment []byte   `protobuf:"bytes,1,opt,name=script_commitment,json=scriptCommitment,proto3" json:"script_commitment,omitempty"`
	ScriptParams     [][]byte `protobuf:"bytes,2,rep,name=script_params,json=scriptParams,proto3" json:"script_params,omitempty"`
}

func (x *UnlockingScript) Reset() {
	*x = UnlockingScript{}
	if protoimpl.UnsafeEnabled {
		mi := &file_models_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnlockingScript) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnlockingScript) ProtoMessage() {}

func (x *UnlockingScript) ProtoReflect() protoreflect.Message {
	mi := &file_models_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnlockingScript.ProtoReflect.Descriptor instead.
func (*UnlockingScript) Descriptor() ([]byte, []int) {
	return file_models_proto_rawDescGZIP(), []int{3}
}

func (x *UnlockingScript) GetScriptCommitment() []byte {
	if x != nil {
		return x.ScriptCommitment
	}
	return nil
}

func (x *UnlockingScript) GetScriptParams() [][]byte {
	if x != nil {
		return x.ScriptParams
	}
	return nil
}

var File_models_proto protoreflect.FileDescriptor

var file_models_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd8,
	0x02, 0x0a, 0x09, 0x53, 0x70, 0x65, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x49, 0x6e,
	0x64, 0x65, 0x78, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x48, 0x61, 0x73,
	0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x48,
	0x61, 0x73, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x61,
	0x73, 0x73, 0x65, 0x74, 0x5f, 0x49, 0x44, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x61,
	0x73, 0x73, 0x65, 0x74, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x73, 0x61, 0x6c, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73, 0x61, 0x6c, 0x74,
	0x12, 0x1b, 0x0a, 0x09, 0x61, 0x63, 0x63, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x08, 0x61, 0x63, 0x63, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1d, 0x0a,
	0x0a, 0x77, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x09, 0x77, 0x61, 0x74, 0x63, 0x68, 0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x3b, 0x0a, 0x10,
	0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x55, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x69,
	0x6e, 0x67, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x52, 0x0f, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b,
	0x69, 0x6e, 0x67, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x22, 0x55, 0x0a, 0x11, 0x57, 0x61, 0x6c,
	0x6c, 0x65, 0x74, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x78, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x74, 0x78,
	0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x6d, 0x74, 0x49, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x05, 0x61, 0x6d, 0x74, 0x49, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x74, 0x4f,
	0x75, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x61, 0x6d, 0x74, 0x4f, 0x75, 0x74,
	0x22, 0xbb, 0x01, 0x0a, 0x08, 0x41, 0x64, 0x64, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x12, 0x0a,
	0x04, 0x61, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64, 0x64,
	0x72, 0x12, 0x3b, 0x0a, 0x10, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x55, 0x6e,
	0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x52, 0x0f, 0x75,
	0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x12, 0x22,
	0x0a, 0x0d, 0x76, 0x69, 0x65, 0x77, 0x5f, 0x70, 0x72, 0x69, 0x76, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x76, 0x69, 0x65, 0x77, 0x50, 0x72, 0x69, 0x76, 0x4b,
	0x65, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12,
	0x1d, 0x0a, 0x0a, 0x77, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x09, 0x77, 0x61, 0x74, 0x63, 0x68, 0x4f, 0x6e, 0x6c, 0x79, 0x22, 0x63,
	0x0a, 0x0f, 0x55, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x53, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x12, 0x2b, 0x0a, 0x11, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x23,
	0x0a, 0x0d, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x73, 0x42, 0x07, 0x5a, 0x05, 0x2e, 0x2e, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_models_proto_rawDescOnce sync.Once
	file_models_proto_rawDescData = file_models_proto_rawDesc
)

func file_models_proto_rawDescGZIP() []byte {
	file_models_proto_rawDescOnce.Do(func() {
		file_models_proto_rawDescData = protoimpl.X.CompressGZIP(file_models_proto_rawDescData)
	})
	return file_models_proto_rawDescData
}

var file_models_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_models_proto_goTypes = []interface{}{
	(*SpendNote)(nil),         // 0: SpendNote
	(*WalletTransaction)(nil), // 1: WalletTransaction
	(*AddrInfo)(nil),          // 2: AddrInfo
	(*UnlockingScript)(nil),   // 3: UnlockingScript
}
var file_models_proto_depIdxs = []int32{
	3, // 0: SpendNote.unlocking_script:type_name -> UnlockingScript
	3, // 1: AddrInfo.unlocking_script:type_name -> UnlockingScript
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_models_proto_init() }
func file_models_proto_init() {
	if File_models_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_models_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SpendNote); i {
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
		file_models_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WalletTransaction); i {
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
		file_models_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddrInfo); i {
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
		file_models_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnlockingScript); i {
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
			RawDescriptor: file_models_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_models_proto_goTypes,
		DependencyIndexes: file_models_proto_depIdxs,
		MessageInfos:      file_models_proto_msgTypes,
	}.Build()
	File_models_proto = out.File
	file_models_proto_rawDesc = nil
	file_models_proto_goTypes = nil
	file_models_proto_depIdxs = nil
}
