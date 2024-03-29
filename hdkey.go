// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"github.com/libp2p/go-libp2p/core/crypto"
	icrypto "github.com/project-illium/ilxd/crypto"
)

const (
	NetworkKeyMacCode     = "/illium/network"
	SpendMasterKeyMacCode = "/illium/spend"
	ViewMasterKeyMacCode  = "/illium/view"
)

type HDPrivateKey struct {
	crypto.PrivKey
	chaincode []byte
}

func (k *HDPrivateKey) Child(n uint32) (*HDPrivateKey, error) {
	mac := hmac.New(sha512.New, k.chaincode)
	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nBytes, n)

	rawKey, err := k.Raw()
	if err != nil {
		return nil, err
	}
	mac.Write(append(rawKey, nBytes...))
	res := mac.Sum(nil)

	var (
		seed    [32]byte
		privKey crypto.PrivKey
	)
	copy(seed[:], res[:32])

	switch k.PrivKey.Type() {
	case icrypto.Libp2pKeyTypeNova:
		privKey, _, err = icrypto.NewNovaKeyFromSeed(seed)
		if err != nil {
			return nil, err
		}
	case icrypto.Libp2pKeyTypeCurve25519:
		privKey, _, err = icrypto.NewCurve25519KeyFromSeed(seed)
		if err != nil {
			return nil, err
		}
	case crypto.Ed25519:
		priv := ed25519.NewKeyFromSeed(seed[:])
		privKey, err = crypto.UnmarshalEd25519PrivateKey(priv)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown HDKey private key type")
	}

	return &HDPrivateKey{
		PrivKey:   privKey,
		chaincode: res[32:],
	}, nil
}

func (k *HDPrivateKey) PrivateKey() crypto.PrivKey {
	return k.PrivKey
}

func seedToNetworkKey(seed []byte) (*HDPrivateKey, error) {
	mac := hmac.New(sha512.New, []byte(NetworkKeyMacCode))
	res := mac.Sum(seed)

	sk := ed25519.NewKeyFromSeed(res[:ed25519.SeedSize])
	privKey, err := crypto.UnmarshalEd25519PrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return &HDPrivateKey{
		PrivKey:   privKey,
		chaincode: res[ed25519.PrivateKeySize:],
	}, nil
}

func seedToSpendMaster(seed []byte) (*HDPrivateKey, error) {
	mac := hmac.New(sha512.New, []byte(SpendMasterKeyMacCode))
	res := mac.Sum(seed)

	var novaSeed [32]byte
	copy(novaSeed[:], res[:32])

	privKey, _, err := icrypto.NewNovaKeyFromSeed(novaSeed)
	if err != nil {
		return nil, err
	}
	return &HDPrivateKey{
		PrivKey:   privKey,
		chaincode: res[ed25519.PrivateKeySize:],
	}, nil
}

func seedToViewMaster(seed []byte) (*HDPrivateKey, error) {
	mac := hmac.New(sha512.New, []byte(ViewMasterKeyMacCode))
	res := mac.Sum(seed)

	var curveSeed [32]byte
	copy(curveSeed[:], res[:32])

	privKey, _, err := icrypto.NewCurve25519KeyFromSeed(curveSeed)
	if err != nil {
		return nil, err
	}
	return &HDPrivateKey{
		PrivKey:   privKey,
		chaincode: res[ed25519.PrivateKeySize:],
	}, nil
}
