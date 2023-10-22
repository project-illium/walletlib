// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	lcrypto "github.com/project-illium/ilxd/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeDecodePrivateKey(t *testing.T) {
	spendKey, _, err := lcrypto.GenerateNovaKey(rand.Reader)
	assert.NoError(t, err)
	spendRaw, err := spendKey.Raw()
	assert.NoError(t, err)

	viewKey, _, err := lcrypto.GenerateCurve25519Key(rand.Reader)
	assert.NoError(t, err)
	viewRaw, err := viewKey.Raw()
	assert.NoError(t, err)

	key := &WalletPrivateKey{}
	copy(key.spendKey[:], spendRaw)
	copy(key.viewKey[:], viewRaw)

	keyStr := EncodePrivateKey(key)

	key2, err := DecodePrivateKey(keyStr)
	assert.NoError(t, err)

	assert.True(t, key.Equals(key2))
}
