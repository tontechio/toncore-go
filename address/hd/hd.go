// Cosmos-SDK: https://github.com/cosmos/cosmos-sdk/blob/master/crypto/hd/hd.pb.go

package hd

// BIP44Params is used as path field in ledger item in Record.
type BIP44Params struct {
	// purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation
	Purpose uint32 `protobuf:"varint,1,opt,name=purpose,proto3" json:"purpose,omitempty"`
	// coin_type is a constant that improves privacy
	CoinType uint32 `protobuf:"varint,2,opt,name=coin_type,json=coinType,proto3" json:"coin_type,omitempty"`
	// account splits the key space into independent user identities
	Account uint32 `protobuf:"varint,3,opt,name=account,proto3" json:"account,omitempty"`
	// change is a constant used for public derivation. Constant 0 is used for external chain and constant 1 for internal
	// chain.
	Change bool `protobuf:"varint,4,opt,name=change,proto3" json:"change,omitempty"`
	// address_index is used as child index in BIP32 derivation
	AddressIndex uint32 `protobuf:"varint,5,opt,name=address_index,json=addressIndex,proto3" json:"address_index,omitempty"`
}
