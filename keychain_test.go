// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo/mock"
	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
	"testing"
	"time"
)

func TestKeychain(t *testing.T) {
	ds := mock.NewMapDatastore()

	_, err := LoadKeychain(ds, &params.RegestParams)
	assert.Error(t, err)

	ent, err := bip39.NewEntropy(256)
	assert.NoError(t, err)
	mnemonic, err := bip39.NewMnemonic(ent)
	assert.NoError(t, err)

	kc, err := NewKeychain(ds, &params.RegestParams, mnemonic)
	assert.NoError(t, err)

	assert.False(t, kc.isEncrypted)
	assert.False(t, kc.isPruned)
	viewkeys, err := kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 1)

	kc, err = LoadKeychain(ds, &params.RegestParams)
	assert.NoError(t, err)

	assert.False(t, kc.isEncrypted)
	assert.False(t, kc.isPruned)
	viewkeys, err = kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 1)

	addr, err := kc.Address()
	assert.NoError(t, err)

	addr2, err := kc.NewAddress()
	assert.NoError(t, err)

	assert.NotEqual(t, addr, addr2)
	viewkeys, err = kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 2)

	addr, err = kc.Address()
	assert.NoError(t, err)
	assert.Equal(t, addr, addr2)

	assert.NoError(t, kc.SetPassphrase("letmein"))
	assert.True(t, kc.isEncrypted)

	_, err = kc.Address()
	assert.NoError(t, err)

	_, err = kc.NewAddress()
	assert.Error(t, err)

	assert.NoError(t, kc.Unlock("letmein", time.Second*10))

	_, err = kc.NewAddress()
	assert.NoError(t, err)
	viewkeys, err = kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 3)

	assert.NoError(t, kc.Lock())
	_, err = kc.NewAddress()
	assert.Error(t, err)

	kc, err = LoadKeychain(ds, &params.RegestParams)
	assert.NoError(t, err)

	assert.True(t, kc.isEncrypted)
	viewkeys, err = kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 3)

	_, err = kc.NewAddress()
	assert.Error(t, err)

	assert.NoError(t, kc.ChangePassphrase("letmein", "mooo"))

	assert.NoError(t, kc.Unlock("mooo", time.Second*10))
	_, err = kc.NewAddress()
	assert.NoError(t, err)
	viewkeys, err = kc.getViewKeys()
	assert.NoError(t, err)
	assert.Len(t, viewkeys, 4)

	assert.NoError(t, kc.Lock())
	assert.Error(t, kc.Unlock("letmein", time.Second*10))

	addrs, err := kc.Addresses()
	assert.NoError(t, err)
	addr, lockingScript, viewKey, err := newAddress(0, []byte{0xff}, &params.MainnetParams)
	assert.NoError(t, err)

	assert.NoError(t, kc.ImportAddress(addr, lockingScript, viewKey))
	addrs2, err := kc.Addresses()
	assert.NoError(t, err)
	assert.Len(t, addrs2, len(addrs)+1)

	addr2, err = kc.Address()
	assert.NoError(t, err)
	assert.NotEqual(t, addr2, addr)

	_, err = kc.addrInfo(viewKey)
	assert.NoError(t, err)
}
