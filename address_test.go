// Copyright (c) 2022 Project Illium
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	"github.com/libp2p/go-libp2p/core/crypto"
	crypto2 "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicAddress(t *testing.T) {
	_, pubkey, err := crypto.GenerateEd25519Key(rand.Reader)
	assert.NoError(t, err)

	_, viewKey, err := crypto2.GenerateCurve25519Key(rand.Reader)
	assert.NoError(t, err)

	pubKeyRaw, err := pubkey.Raw()
	assert.NoError(t, err)

	us := types.UnlockingScript{
		ScriptCommitment: MockBasicUnlockScriptCommitment,
		ScriptParams:     [][]byte{pubKeyRaw},
	}

	addr, err := NewBasicAddress(us, viewKey, &params.MainnetParams)
	assert.NoError(t, err)

	addr2, err := DecodeAddress(addr.String(), &params.MainnetParams)

	if addr2.String() != addr.String() {
		t.Error("Decoded address does not match encoded")
	}
}
