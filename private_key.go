// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	crypto2 "github.com/project-illium/ilxd/crypto"
)

func init() {
	crypto.PrivKeyUnmarshallers[Libp2pKeyTypeWalletKey] = UnmarshalWalletPrivateKey
}

const (
	Libp2pKeyTypeWalletKey = pb.KeyType(5)
)

type WalletPrivateKey struct {
	spendKey [32]byte
	viewKey  [32]byte
}

// Equals checks whether two PubKeys are the same
func (k *WalletPrivateKey) Equals(ck crypto.Key) bool {
	pk, ok := ck.(*WalletPrivateKey)
	if !ok {
		return false
	}
	return pk.viewKey == k.viewKey && pk.spendKey == k.spendKey
}

// Raw returns the raw bytes of the key (not wrapped in the
// libp2p-crypto protobuf).
//
// This function is the inverse of {Priv,Pub}KeyUnmarshaler.
func (k *WalletPrivateKey) Raw() ([]byte, error) {
	var ret [64]byte
	copy(ret[:32], k.spendKey[:])
	copy(ret[32:], k.viewKey[:])
	return ret[:], nil
}

// Type returns the protobuf key type.
func (k *WalletPrivateKey) Type() pb.KeyType {
	return Libp2pKeyTypeWalletKey
}

// Cryptographically sign the given bytes
func (k *WalletPrivateKey) Sign([]byte) ([]byte, error) {
	return nil, crypto2.ErrSigNoop
}

// Return a public key paired with this private key
func (k *WalletPrivateKey) GetPublic() crypto.PubKey {
	return nil
}

// UnmarshalWalletPrivateKey returns a private key from input bytes.
func UnmarshalWalletPrivateKey(data []byte) (crypto.PrivKey, error) {
	if len(data) != 64 {
		return nil, errors.New("invalid private key len")
	}

	pk := &WalletPrivateKey{}
	copy(pk.spendKey[:], data[:32])
	copy(pk.viewKey[:], data[32:])

	return pk, nil
}
