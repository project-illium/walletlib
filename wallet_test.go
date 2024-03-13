// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	"errors"
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/repo/mock"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/walletlib/client"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func mockAddress() (Address, types.LockingScript, lcrypto.PrivKey, error) {
	viewPriv, viewPub, err := crypto.GenerateCurve25519Key(rand.Reader)
	if err != nil {
		return nil, types.LockingScript{}, nil, err
	}
	_, spendKey, err := crypto.GenerateNovaKey(rand.Reader)
	if err != nil {
		return nil, types.LockingScript{}, nil, err
	}
	pubX, pubY := spendKey.(*crypto.NovaPublicKey).ToXY()

	if err != nil {
		return nil, types.LockingScript{}, nil, err
	}

	lockingScript := types.LockingScript{
		ScriptCommitment: types.NewID(zk.BasicTransferScriptCommitment()),
		LockingParams:    [][]byte{pubX, pubY},
	}

	addr, err := NewBasicAddress(lockingScript, viewPub, &params.RegestParams)
	if err != nil {
		return nil, types.LockingScript{}, nil, err
	}
	return addr, lockingScript, viewPriv, nil
}

func mockPublicAddress() (Address, error) {
	_, spendKey, err := crypto.GenerateNovaKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubX, pubY := spendKey.(*crypto.NovaPublicKey).ToXY()

	lockingParams := makePublicAddressLockingParams(pubX, pubY)

	addr, err := NewPublicAddress(lockingParams, &params.RegestParams)
	if err != nil {
		return nil, err
	}
	return addr, nil
}

func TestWallet(t *testing.T) {
	ds := mock.NewMapDatastore()

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		BlockchainSource(&client.InternalClient{
			BroadcastFunc: func(tx *transactions.Transaction) error { return nil },
			GetBlocksFunc: func(from, to uint32) ([]*blocks.Block, uint32, error) { return nil, 0, nil },
			GetAccumulatorCheckpointFunc: func(height uint32) (*blockchain.Accumulator, uint32, error) {
				return nil, 0, blockchain.ErrNoCheckpoint
			},
		}),
		Params(&params.RegestParams),
		Prover(&zk.MockProver{}),
	}...)
	assert.NoError(t, err)

	w.connectBlock(params.RegestParams.GenesisBlock, w.scanner, w.accdb, false)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount, types.State{})
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
	nullifier, err := types.CalculateNullifier(notes[0].AccIndex, salt, notes[0].LockingScript.ScriptCommitment, notes[0].LockingScript.LockingParams...)
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

	txs, err := w.Transactions(0, -1)
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	assert.Equal(t, uint32(2), w.chainHeight)

	// Test import
	addr, lockingScript, viewPriv, err := mockAddress()
	assert.NoError(t, err)

	toAmount = types.Amount(1000000)
	output, _, err = buildOutput(addr, toAmount, types.State{})
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

	txs, err = w.Transactions(0, -1)
	assert.NoError(t, err)
	assert.Len(t, txs, 2)

	// Import and rescan
	w.chainClient.(*client.InternalClient).GetBlocksFunc = func(from, to uint32) ([]*blocks.Block, uint32, error) {
		var ret []*blocks.Block
		switch from {
		case 1:
			ret = append(ret, blk1)
		case 2:
			ret = append(ret, blk2)
		case 3:
			ret = append(ret, blk3)
		}
		if from == 1 && to == 2 {
			ret = append(ret, blk2)
		} else if from == 1 && to == 3 {
			ret = append(ret, blk2, blk3)
		} else if from == 2 && to == 3 {
			ret = append(ret, blk3)
		}
		return ret, 3, nil
	}

	assert.NoError(t, w.ImportAddress(addr, lockingScript, viewPriv, true, 1))
	<-time.After(time.Second * 1)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	balance, err = w.Balance()
	assert.NoError(t, err)
	assert.Equal(t, toAmount, balance)

	txs, err = w.Transactions(0, -1)
	assert.NoError(t, err)
	assert.Len(t, txs, 3)
}

func TestTransactions(t *testing.T) {
	ds := mock.NewMapDatastore()

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		BlockchainSource(&client.InternalClient{
			BroadcastFunc: func(tx *transactions.Transaction) error { return nil },
			GetBlocksFunc: func(from, to uint32) ([]*blocks.Block, uint32, error) { return nil, 0, nil },
			GetAccumulatorCheckpointFunc: func(height uint32) (*blockchain.Accumulator, uint32, error) {
				return nil, 0, blockchain.ErrNoCheckpoint
			},
		}),
		Params(&params.RegestParams),
		Prover(&zk.MockProver{}),
	}...)
	assert.NoError(t, err)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount, types.State{})
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

	// This should error due to spend lock on the utxo
	err = w.Stake([]types.ID{types.NewID(notes[0].Commitment)})
	assert.Error(t, err)

	// Delete the spend lock
	delete(w.inflightUtxos, types.NewID(notes[0].Commitment))

	// Stake
	err = w.Stake([]types.ID{types.NewID(notes[0].Commitment)})
	assert.NoError(t, err)

	// This should error due to spend lock
	_, err = w.SweepWallet(addr, 10)
	assert.Error(t, err)

	// Delete the spend lock
	delete(w.inflightUtxos, types.NewID(notes[0].Commitment))

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
		Prover(&zk.MockProver{}),
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		BlockchainSource(&client.InternalClient{
			BroadcastFunc: func(tx *transactions.Transaction) error {
				go func() { broadcastChan <- tx }()
				return nil
			},
			GetBlocksFunc: func(from, to uint32) ([]*blocks.Block, uint32, error) { return nil, 0, nil },
			GetAccumulatorCheckpointFunc: func(height uint32) (*blockchain.Accumulator, uint32, error) {
				return nil, 0, blockchain.ErrNoCheckpoint
			},
		}),
		Params(&params.RegestParams),
	}...)
	assert.NoError(t, err)

	addr, err := w.Address()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount, types.State{})
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

	// 1 utxo in wallet
	w.ConnectBlock(blk0)

	output, _, err = buildOutput(addr, toAmount, types.State{})
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

	// 2 utxos in wallet
	w.ConnectBlock(blk1)

	notes, err := w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 2)

	// Stake
	var salt [32]byte
	copy(salt[:], notes[1].Salt)
	nullifier, err := types.CalculateNullifier(notes[1].AccIndex, salt, notes[1].LockingScript.ScriptCommitment, notes[1].LockingScript.LockingParams...)
	assert.NoError(t, err)

	blk2 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 2},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StakeTransaction{
				Nullifier: nullifier[:],
			}),
		},
	}
	// 2 utxos in wallet (1 staked)
	w.ConnectBlock(blk2)

	// Spend
	addr, _, _, err = mockAddress()
	assert.NoError(t, err)
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx := <-broadcastChan
	blk3 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 3},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}

	// 2 utoxs in wallet (1 staked, 1 change)
	w.ConnectBlock(blk3)

	cbtx, err := w.BuildCoinbaseTransaction(types.Amount(2000000), nil, priv)
	assert.NoError(t, err)

	blk4 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 4},
		Transactions: []*transactions.Transaction{
			cbtx,
		},
	}
	// 3 utxos in wallet (1 staked)
	w.ConnectBlock(blk4)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 3)

	// Spend
	addr, _, _, err = mockAddress()
	assert.NoError(t, err)
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk5 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 5},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}

	// 3 utxos in wallet (1 staked)
	w.ConnectBlock(blk5)

	// Spend
	addr, _, _, err = mockAddress()
	assert.NoError(t, err)
	_, err = w.Spend(addr, types.Amount(900000), types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk6 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 6},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	// 3 utxos in wallet (1 staked)
	w.ConnectBlock(blk6)

	// Sweep
	addr, _, _, err = mockAddress()
	assert.NoError(t, err)
	_, err = w.SweepWallet(addr, types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk7 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 7},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	// 1 utxo in wallet (1 staked)
	w.ConnectBlock(blk7)

	// Receive
	addr, err = w.Address()
	assert.NoError(t, err)
	output, _, err = buildOutput(addr, toAmount, types.State{})
	assert.NoError(t, err)
	blk8 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 8},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	// 2 utxos in wallet (1 staked)
	w.ConnectBlock(blk8)

	// Timelock
	_, err = w.TimelockCoins(types.Amount(800000), time.Now().Add(time.Hour), types.Amount(10))
	assert.NoError(t, err)

	tx = <-broadcastChan
	blk9 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 9},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	// 3 utxos in wallet (1 staked, 1 timelocked, 1 change)
	w.ConnectBlock(blk9)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 3)

	timeLocked := false
	for _, n := range notes {
		if n.LockedUntil > 0 {
			timeLocked = true
			break
		}
	}
	assert.True(t, timeLocked)
}

func TestPublicAddresses(t *testing.T) {
	ds := mock.NewMapDatastore()

	broadcast := make(chan *transactions.Transaction)

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		BlockchainSource(&client.InternalClient{
			BroadcastFunc: func(tx *transactions.Transaction) error {
				go func() {
					broadcast <- tx
				}()
				return nil
			},
			GetBlocksFunc: func(from, to uint32) ([]*blocks.Block, uint32, error) { return nil, 0, nil },
			GetAccumulatorCheckpointFunc: func(height uint32) (*blockchain.Accumulator, uint32, error) {
				return nil, 0, blockchain.ErrNoCheckpoint
			},
		}),
		Params(&params.RegestParams),
		Prover(&zk.MockProver{}),
	}...)
	assert.NoError(t, err)

	addr, err := w.PublicAddress()
	assert.NoError(t, err)

	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount, types.State{})
	assert.NoError(t, err)

	// Receive to public address
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
	assert.Equal(t, notes[0].Address, addr.String())

	addr2, err := mockPublicAddress()
	assert.NoError(t, err)

	// Spend the received coins to a public address
	amt := types.Amount(50000)
	_, err = w.Spend(addr2, amt, 10)
	assert.NoError(t, err)

	tx := <-broadcast

	blk2 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 2},
		Transactions: []*transactions.Transaction{
			tx,
		},
	}
	w.ConnectBlock(blk2)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)
	assert.NotEqual(t, notes[0].Address, addr.String())

	// Spend the received coins to an exchange address
	exAddr := &ExchangeAddress{
		params:  addr.(*PublicAddress).params,
		version: 3,
		hash:    addr.(*PublicAddress).hash,
	}
	amt = types.Amount(50000)
	_, err = w.Spend(exAddr, amt, 10)
	// This should trigger insufficient funds because the
	// change in the previous transaction were sent to a
	// private address.
	assert.True(t, errors.Is(err, ErrInsufficientFunds))

	// Get some more public coins and try again
	blk3 := &blocks.Block{
		Header: &blocks.BlockHeader{Height: 1},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk3)

	_, err = w.Spend(exAddr, amt, 10)
	assert.NoError(t, err)
}

func TestRescan(t *testing.T) {
	// Three utxos in the wallet
	// One of which is spent

	ds := mock.NewMapDatastore()

	broadcast := make(chan *transactions.Transaction)

	var (
		blk1, blk2, blk3, blk4 *blocks.Block
	)

	w, err := NewWallet([]Option{
		Datastore(ds),
		DataDir(repo.DefaultHomeDir),
		BlockchainSource(&client.InternalClient{
			BroadcastFunc: func(tx *transactions.Transaction) error {
				go func() {
					broadcast <- tx
				}()
				return nil
			},
			GetBlocksFunc: func(from, to uint32) ([]*blocks.Block, uint32, error) {
				if blk1 == nil {
					return nil, 0, nil
				}
				return []*blocks.Block{blk1, blk2, blk3, blk4}, 4, nil
			},
			GetAccumulatorCheckpointFunc: func(height uint32) (*blockchain.Accumulator, uint32, error) {
				return nil, 0, blockchain.ErrNoCheckpoint
			},
		}),
		Params(&params.RegestParams),
		Prover(&zk.MockProver{}),
	}...)
	assert.NoError(t, err)
	w.connectBlock(w.params.GenesisBlock, w.scanner, w.accdb, false)

	addr, err := w.Address()
	assert.NoError(t, err)

	// Utxo 1
	toAmount := types.Amount(1000000)
	output, _, err := buildOutput(addr, toAmount, types.State{})
	assert.NoError(t, err)

	blk1 = &blocks.Block{
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

	// Utxo 2
	toAmount = types.Amount(2000000)
	output, _, err = buildOutput(addr, toAmount, types.State{})
	assert.NoError(t, err)

	blk2 = &blocks.Block{
		Header: &blocks.BlockHeader{Height: 2},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk2)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 2)

	// Spend utxo 1
	var nullifier types.Nullifier
	for n, c := range w.nullifiers {
		if c.Compare(types.NewID(notes[0].Commitment)) == 0 {
			nullifier = n
			assert.NoError(t, err)
		}
	}
	blk3 = &blocks.Block{
		Header: &blocks.BlockHeader{Height: 3},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Nullifiers: [][]byte{
					nullifier.Bytes(),
				},
			}),
		},
	}
	w.ConnectBlock(blk3)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 1)

	// Utxo 3
	toAmount = types.Amount(3000000)
	output, _, err = buildOutput(addr, toAmount, types.State{})
	assert.NoError(t, err)

	blk4 = &blocks.Block{
		Header: &blocks.BlockHeader{Height: 4},
		Transactions: []*transactions.Transaction{
			transactions.WrapTransaction(&transactions.StandardTransaction{
				Outputs: []*transactions.Output{output},
			}),
		},
	}
	w.ConnectBlock(blk4)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 2)

	err = w.rescanWallet(0)
	assert.NoError(t, err)

	notes, err = w.Notes()
	assert.NoError(t, err)
	assert.Len(t, notes, 2)
	assert.Len(t, w.nullifiers, 2)
}
