// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/repo/mock"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestWallet(t *testing.T) {
	ds := mock.NewMapDatastore()

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		GetBlockFunction(func(height uint32) (*blocks.Block, error) { return nil, nil }),
		GetAccumulatorCheckpointFunction(func(height uint32) (*blockchain.Accumulator, uint32, error) {
			return nil, 0, blockchain.ErrNoCheckpoint
		}),
		BroadcastFunction(func(tx *transactions.Transaction) error { return nil }),
		ProofsSourceFunction(func(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error) {
			return nil, types.ID{}, nil
		}),
		Params(&params.RegestParams),
	}...)
	assert.NoError(t, err)

	addr, err := w.Address()
	assert.NoError(t, err)

	scriptHash := addr.ScriptHash()
	var salt [32]byte
	rand.Read(salt[:])

	note := &types.SpendNote{
		ScriptHash: scriptHash[:],
		Amount:     1000000,
		AssetID:    types.IlliumCoinID,
		State:      [128]byte{},
		Salt:       salt,
	}
	ser := note.Serialize()
	commitment, err := note.Commitment()
	assert.NoError(t, err)
	ciphertext, err := addr.ViewKey().(*crypto.Curve25519PublicKey).Encrypt(ser)
	assert.NoError(t, err)

	// Receive
	blk1 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 1},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{
					{
						Commitment: commitment[:],
						Ciphertext: ciphertext,
					},
				},
			}),
		},
	}
	w.ConnectBlock(blk1)

	notes, err := w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	balance, err := w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, note.Amount, balance)

	nullifier, err := types.CalculateNullifier(notes[0].AccIndex, salt, notes[0].UnlockingScript.ScriptCommitment, notes[0].UnlockingScript.ScriptParams...)
	assert.NoError(t, err)

	// Spend
	blk2 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 2},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Nullifiers: [][]byte{
					nullifier[:],
				},
			}),
		},
	}
	w.ConnectBlock(blk2)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 0)
	balance, err = w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, types.Amount(0), balance)

	txs, err := w.GetTransactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	assert.Equal(t, uint32(2), w.chainHeight)

	// Test import
	viewPriv, viewPub, err := crypto.GenerateCurve25519Key(rand.Reader)
	assert.NoError(t, err)
	_, spendKey, err := lcrypto.GenerateEd25519Key(rand.Reader)
	assert.NoError(t, err)
	rawSpend, err := spendKey.Raw()
	assert.NoError(t, err)
	unlockingScript := types.UnlockingScript{
		ScriptCommitment: mockBasicUnlockScriptCommitment,
		ScriptParams:     [][]byte{rawSpend},
	}

	addr, err = NewBasicAddress(unlockingScript, viewPub, &params.RegestParams)
	assert.NoError(t, err)

	scriptHash = addr.ScriptHash()
	var salt2 [32]byte
	rand.Read(salt[:])

	note = &types.SpendNote{
		ScriptHash: scriptHash[:],
		Amount:     1000000,
		AssetID:    types.IlliumCoinID,
		State:      [128]byte{},
		Salt:       salt2,
	}
	ser = note.Serialize()
	commitment, err = note.Commitment()
	assert.NoError(t, err)
	ciphertext, err = viewPub.(*crypto.Curve25519PublicKey).Encrypt(ser)
	assert.NoError(t, err)

	// Receive to unknown addr
	blk3 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 3},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{
					{
						Commitment: commitment[:],
						Ciphertext: ciphertext,
					},
				},
			}),
		},
	}
	w.ConnectBlock(blk3)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 0)
	balance, err = w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, types.Amount(0), balance)

	txs, err = w.GetTransactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	w.getBlocksFunc = func(height uint32) (*blocks.Block, error) {
		if height == 1 {
			return blk1, nil
		} else if height == 2 {
			return blk2, nil
		}
		return blk3, nil
	}

	assert.NoError(t, w.ImportAddress(addr, unlockingScript, viewPriv, true, 1))
	<-time.After(time.Second * 1)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	balance, err = w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, note.Amount, balance)

	txs, err = w.GetTransactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 3)
}
