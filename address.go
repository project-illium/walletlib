// Copyright (c) 2022 Project Illium
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/libp2p/go-libp2p/core/crypto"
	crypto2 "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/zk"
)

var publicAddrScriptHash []byte

func init() {
	lockingScript := types.LockingScript{
		ScriptCommitment: types.NewID(zk.PublicAddressScriptCommitment()),
		LockingParams:    nil,
	}
	scriptHash, err := lockingScript.Hash()
	if err != nil {
		panic(err)
	}
	publicAddrScriptHash = scriptHash.Bytes()
}

const ScriptHashLength = hash.HashSize

type Address interface {
	EncodeAddress() string
	String() string
	ScriptHash() [32]byte
	ViewKey() crypto.PubKey
}

type BasicAddress struct {
	params  *params.NetworkParams
	version byte
	hash    [32]byte
	viewKey crypto.PubKey
}

func NewBasicAddress(script types.LockingScript, viewKey crypto.PubKey, params *params.NetworkParams) (*BasicAddress, error) {
	_, ok := viewKey.(*crypto2.Curve25519PublicKey)
	if !ok {
		return nil, errors.New("viewKey must be of type Curve25519PublicKey")
	}

	h, err := script.Hash()
	if err != nil {
		return nil, err
	}
	var h2 [32]byte
	copy(h2[:], h[:])

	return &BasicAddress{
		hash:    h2,
		viewKey: viewKey,
		version: 1,
		params:  params,
	}, nil
}

func (a *BasicAddress) ScriptHash() [32]byte {
	return a.hash
}

func (a *BasicAddress) ViewKey() crypto.PubKey {
	return a.viewKey
}

func (a *BasicAddress) EncodeAddress() string {
	keyBytes, err := a.viewKey.Raw()
	if err != nil {
		return ""
	}
	converted, err := bech32.ConvertBits(append(a.hash[:], keyBytes...), 8, 5, true)
	if err != nil {
		return ""
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = a.version
	copy(combined[1:], converted)
	ret, err := bech32.EncodeM(a.params.AddressPrefix, combined)
	if err != nil {
		return ""
	}
	return ret
}

func (a *BasicAddress) String() string {
	return a.EncodeAddress()
}

type PublicAddress struct {
	params  *params.NetworkParams
	version byte
	hash    [32]byte
}

func NewPublicAddress(lockingParams string, params *params.NetworkParams) (*PublicAddress, error) {
	h, err := zk.LurkCommit(lockingParams)
	if err != nil {
		return nil, err
	}

	var h2 [32]byte
	copy(h2[:], h[:])

	return &PublicAddress{
		hash:    h2,
		version: 2,
		params:  params,
	}, nil
}

func (a *PublicAddress) ScriptHash() [32]byte {
	return a.hash
}

func (a *PublicAddress) ViewKey() crypto.PubKey {
	return nil
}

func (a *PublicAddress) EncodeAddress() string {
	converted, err := bech32.ConvertBits(a.hash[:], 8, 5, true)
	if err != nil {
		return ""
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = a.version
	copy(combined[1:], converted)
	ret, err := bech32.EncodeM(a.params.AddressPrefix, combined)
	if err != nil {
		return ""
	}
	return ret
}

func (a *PublicAddress) String() string {
	return a.EncodeAddress()
}

func DecodeAddress(addr string, params *params.NetworkParams) (Address, error) {
	// Decode the bech32 encoded address.
	_, data, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return nil, err
	}

	// The first byte of the decoded address is the version, it must exist.
	if len(data) < 1 {
		return nil, fmt.Errorf("no version")
	}

	switch data[0] {
	case 0x01:
		// The remaining characters of the address returned are grouped into
		// words of 5 bits. In order to restore the original address bytes,
		// we'll need to regroup into 8 bit words.
		regrouped, err := bech32.ConvertBits(data[1:], 5, 8, false)
		if err != nil {
			return nil, err
		}

		var h2 [32]byte
		copy(h2[:], regrouped[:ScriptHashLength])

		pub, err := crypto2.UnmarshalCurve25519PublicKey(regrouped[ScriptHashLength:])
		if err != nil {
			return nil, err
		}

		ba := BasicAddress{
			params:  params,
			version: data[0],
			hash:    h2,
			viewKey: pub,
		}

		return &ba, nil
	case 0x02:
		regrouped, err := bech32.ConvertBits(data[1:], 5, 8, false)
		if err != nil {
			return nil, err
		}

		var h2 [32]byte
		copy(h2[:], regrouped[:ScriptHashLength])

		pa := PublicAddress{
			params:  params,
			version: data[0],
			hash:    h2,
		}

		return &pa, nil
	default:
		return nil, fmt.Errorf("unknown address version")
	}
}
