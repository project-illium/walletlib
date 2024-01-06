// Copyright (c) 2022 Project Illium
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicAddress(t *testing.T) {
	_, pubkey, err := crypto.GenerateNovaKey(rand.Reader)
	assert.NoError(t, err)

	_, viewKey, err := crypto.GenerateCurve25519Key(rand.Reader)
	assert.NoError(t, err)

	pubX, pubY := pubkey.(*crypto.NovaPublicKey).ToXY()

	us := types.LockingScript{
		ScriptCommitment: types.ID{},
		LockingParams:    [][]byte{pubX, pubY},
	}

	addr, err := NewBasicAddress(us, viewKey, &params.MainnetParams)
	assert.NoError(t, err)

	addr2, err := DecodeAddress(addr.String(), &params.MainnetParams)
	assert.NoError(t, err)

	if addr2.String() != addr.String() {
		t.Error("Decoded address does not match encoded")
	}
}
