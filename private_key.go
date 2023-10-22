// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	crypto2 "github.com/project-illium/ilxd/crypto"
	icrypto "github.com/project-illium/ilxd/crypto"
)

const WalletKeyPrefix = "priv"

func init() {
	crypto.PrivKeyUnmarshallers[Libp2pKeyTypeWalletKey] = UnmarshalWalletPrivateKey
}

const (
	Libp2pKeyTypeWalletKey = pb.KeyType(6)
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

func (k *WalletPrivateKey) SpendKey() crypto.PrivKey {
	sk, _ := crypto2.UnmarshalNovaPrivateKey(k.spendKey[:])
	return sk
}

func (k *WalletPrivateKey) ViewKey() crypto.PrivKey {
	sk, _ := icrypto.UnmarshalCurve25519PrivateKey(k.viewKey[:])
	return sk
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

func EncodePrivateKey(key *WalletPrivateKey) string {
	keyBytes, err := key.Raw()
	if err != nil {
		return ""
	}
	converted, err := bech32.ConvertBits(keyBytes, 8, 5, true)
	if err != nil {
		return ""
	}
	ret, err := bech32.EncodeM(WalletKeyPrefix, converted)
	if err != nil {
		return ""
	}
	return ret
}

func DecodePrivateKey(key string) (crypto.PrivKey, error) {
	_, data, err := bech32.DecodeNoLimit(key)
	if err != nil {
		return nil, err
	}

	// The remaining characters of the key returned are grouped into
	// words of 5 bits. In order to restore the original key bytes,
	// we'll need to regroup into 8 bit words.
	regrouped, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}
	return UnmarshalWalletPrivateKey(regrouped)
}
