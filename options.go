// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
)

// Option is configuration option function for the blockchain
type Option func(cfg *config) error

// Params identifies which chain parameters the chain is associated
// with.
//
// This option is required.
func Params(params *params.NetworkParams) Option {
	return func(cfg *config) error {
		cfg.params = params
		return nil
	}
}

// DataDir is the directory use for the wallet
//
// This option is required
func DataDir(dataDir string) Option {
	return func(cfg *config) error {
		cfg.dataDir = dataDir
		return nil
	}
}

// Datastore is an implementation of the repo.Datastore interface
func Datastore(ds repo.Datastore) Option {
	return func(cfg *config) error {
		cfg.datastore = ds
		return nil
	}
}

// MnemonicSeed is an optional option that allows the user to set
// a custom seed. Also useful for restoring from seed.
func MnemonicSeed(mnemonic string) Option {
	return func(cfg *config) error {
		cfg.mnemonic = mnemonic
		return nil
	}
}

// FeePerKB sets the fee per kilobyte to use for sending transactions.
func FeePerKB(fpkb types.Amount) Option {
	return func(cfg *config) error {
		cfg.feePerKB = fpkb
		return nil
	}
}

// ProofsSourceFunction is a function that looks up and returns an inclusion
// proof for a given commitment.
//
// This function is not optional.
func ProofsSourceFunction(proofSource ProofsSource) Option {
	return func(cfg *config) error {
		cfg.fetchProofsFunc = proofSource
		return nil
	}
}

// BroadcastFunction is a function to broadcast a transaction to the
// network.
//
// This function is not optional.
func BroadcastFunction(broadcast BroadcastFunc) Option {
	return func(cfg *config) error {
		cfg.broadcastFunc = broadcast
		return nil
	}
}

// GetBlockFunction is a function to fetch a block from the chain
// given the height.
//
// This function is not optional.
func GetBlockFunction(getBlock GetBlockFunc) Option {
	return func(cfg *config) error {
		cfg.getBlockFunc = getBlock
		return nil
	}
}

// GetAccumulatorCheckpointFunction is a function to fetch an accumulator checkpoint
// from the blockchain.
//
// This function is not optional.
func GetAccumulatorCheckpointFunction(getAccFunc GetAccumulatorCheckpointFunc) Option {
	return func(cfg *config) error {
		cfg.getAccFunc = getAccFunc
		return nil
	}
}

type config struct {
	datastore       repo.Datastore
	params          *params.NetworkParams
	feePerKB        types.Amount
	broadcastFunc   BroadcastFunc
	fetchProofsFunc ProofsSource
	getBlockFunc    GetBlockFunc
	getAccFunc      GetAccumulatorCheckpointFunc
	dataDir         string
	mnemonic        string
}

func (c *config) validate() error {
	if c.params == nil {
		return errors.New("params cannot be nil")
	}
	if c.dataDir == "" {
		return errors.New("dataDir cannot be empty")
	}
	if c.broadcastFunc == nil {
		return errors.New("broadcastfunc cannot be nil")
	}
	if c.fetchProofsFunc == nil {
		return errors.New("fetchProofsFunc cannot be nil")
	}
	if c.getBlockFunc == nil {
		return errors.New("getBlockFunc cannot be nil")
	}
	if c.getAccFunc == nil {
		return errors.New("getAccFunc cannot be nil")
	}
	return nil
}
