// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	"github.com/project-illium/ilxd/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyDerivation(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)

	message := []byte("secret message")

	master, err := seedToSpendMaster(seed)
	assert.NoError(t, err)

	childPriv, err := master.Child(0)
	assert.NoError(t, err)
	childPub := childPriv.GetPublic()

	childPriv2, err := master.Child(1)
	assert.NoError(t, err)

	assert.False(t, childPriv.Equals(childPriv2))

	sig, err := childPriv.Sign(message)
	assert.NoError(t, err)

	valid, err := childPub.Verify(message, sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	master, err = seedToViewMaster(seed)
	assert.NoError(t, err)

	childPriv, err = master.Child(0)
	assert.NoError(t, err)
	childPub = childPriv.GetPublic()

	cipherText, err := childPub.(*crypto.Curve25519PublicKey).Encrypt(message)
	assert.NoError(t, err)

	plaintext, err := childPriv.PrivKey.(*crypto.Curve25519PrivateKey).Decrypt(cipherText)
	assert.NoError(t, err)

	assert.Equal(t, message, plaintext)
}
