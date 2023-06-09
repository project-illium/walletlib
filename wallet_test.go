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

func mockAddress() (Address, types.UnlockingScript, lcrypto.PrivKey, error) {
	viewPriv, viewPub, err := crypto.GenerateCurve25519Key(rand.Reader)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, nil
	}
	_, spendKey, err := lcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, nil
	}
	rawSpend, err := spendKey.Raw()
	if err != nil {
		return nil, types.UnlockingScript{}, nil, nil
	}
	unlockingScript := types.UnlockingScript{
		ScriptCommitment: MockBasicUnlockScriptCommitment,
		ScriptParams:     [][]byte{rawSpend},
	}

	addr, err := NewBasicAddress(unlockingScript, viewPub, &params.RegestParams)
	if err != nil {
		return nil, types.UnlockingScript{}, nil, nil
	}
	return addr, unlockingScript, viewPriv, nil
}

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
		Params(&params.RegestParams),
	}...)
	assert.NoError(t, err)

	w.connectBlock(params.RegestParams.GenesisBlock, w.scanner, w.accdb, false)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount)
	assert.NoError(t, err)

	// Receive
	blk1 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 1},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk1)

	notes, err := w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	balance, err := w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, toAmount, balance)

	var salt [32]byte
	copy(salt[:], notes[0].Salt)
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

	txs, err := w.Transactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	assert.Equal(t, uint32(2), w.chainHeight)

	// Test import
	addr, unlockingScript, viewPriv, err := mockAddress()
	assert.NoError(t, err)

	toAmount = types.Amount(1000000)
	output, _, err = buildOutput(addr, toAmount)
	assert.NoError(t, err)

	// Receive to unknown addr
	blk3 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 3},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
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

	txs, err = w.Transactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	// Import and rescan
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
	assert.Equal(t, toAmount, balance)

	txs, err = w.Transactions()
	assert.NoError(t, err)
	assert.Len(t, txs, 3)
}

func TestTransactions(t *testing.T) {
	ds := mock.NewMapDatastore()

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		GetBlockFunction(func(height uint32) (*blocks.Block, error) { return nil, nil }),
		GetAccumulatorCheckpointFunction(func(height uint32) (*blockchain.Accumulator, uint32, error) {
			return nil, 0, blockchain.ErrNoCheckpoint
		}),
		BroadcastFunction(func(tx *transactions.Transaction) error { return nil }),
		Params(&params.RegestParams),
	}...)
	assert.NoError(t, err)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount)
	assert.NoError(t, err)

	// Receive
	blk1 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 1},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk1)

	addr, _, _, err = mockAddress()
	assert.NoError(t, err)

	// Spend the received coins
	amt := types.Amount(500000)
	_, err = w.Spend(addr, amt, 10)
	assert.NoError(t, err)

	// Create raw tx
	notes, err := w.Notes()
	assert.NoError(t, err)

	_, err = w.CreateRawTransaction([]*RawInput{{Commitment: notes[0].Commitment}}, []*RawOutput{{Addr: addr, Amount: amt}}, true, 0)
	assert.NoError(t, err)

	// Stake
	err = w.Stake([]types.ID{types.NewID(notes[0].Commitment)})
	assert.NoError(t, err)

	// Sweep
	_, err = w.SweepWallet(addr, 10)
	assert.NoError(t, err)
}

func TestCoinbaseAndSpends(t *testing.T) {
	ds := mock.NewMapDatastore()
	priv, _, err := lcrypto.GenerateEd25519Key(rand.Reader)
	assert.NoError(t, err)

	broadcastChan := make(chan *transactions.Transaction)
	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		GetBlockFunction(func(height uint32) (*blocks.Block, error) { return nil, nil }),
		GetAccumulatorCheckpointFunction(func(height uint32) (*blockchain.Accumulator, uint32, error) {
			return nil, 0, blockchain.ErrNoCheckpoint
		}),
		BroadcastFunction(func(tx *transactions.Transaction) error {
			go func() { broadcastChan <- tx }()
			return nil
		}),
		Params(&params.RegestParams),
	}...)
	assert.NoError(t, err)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount)
	assert.NoError(t, err)

	// Receive
	blk0 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 0},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk0)

	output, _, err = buildOutput(addr, toAmount)
	assert.NoError(t, err)

	// Receive2
	blk1 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 1},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk1)

	notes, err := w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 2)

	// Stake
	var salt [32]byte
	copy(salt[:], notes[1].Salt)
	nullifier, err := types.CalculateNullifier(notes[1].AccIndex, salt, notes[1].UnlockingScript.ScriptCommitment, notes[1].UnlockingScript.ScriptParams...)
	assert.NoError(t, err)
	blk2 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 2},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StakeTransaction{
				Nullifier: nullifier[:],
			}),
		},
	}
	w.ConnectBlock(blk2)

	// Spend
	addr, _, _, err = mockAddress()
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx := <-broadcastChan
	blk3 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 3},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	w.ConnectBlock(blk3)

	cbtx, err := w.BuildCoinbaseTransaction(types.Amount(2000000), nil, priv)
	assert.NoError(t, err)

	blk4 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 4},
		Transactions: []*transactions.Transaction{
			cbtx,
		},
	}
	w.ConnectBlock(blk4)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 3)

	// Spend
	addr, _, _, err = mockAddress()
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk5 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 5},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	w.ConnectBlock(blk5)

	// Spend
	addr, _, _, err = mockAddress()
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk6 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 6},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	w.ConnectBlock(blk6)

	// Sweep
	addr, _, _, err = mockAddress()
	_, err = w.SweepWallet(addr, types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk7 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 7},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	w.ConnectBlock(blk7)
}
