// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/logger"
	"time"
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

// Prover is an instance of the zk.Prover interface that is
// used to create the zk proofs.
//
// This option is required.
func Prover(prover zk.Prover) Option {
	return func(cfg *config) error {
		cfg.prover = prover
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

// BlockchainSource is an implementation of the BlockchainClient that provides
// access to blockchain data.
//
// This is not optional.
func BlockchainSource(client BlockchainClient) Option {
	return func(cfg *config) error {
		cfg.chainClient = client
		return nil
	}
}

// Birthday sets the birthday of this wallet. This should be used by LiteClients
// when restoring from seed. Otherwise, it is not needed.
//
// Note: use MinBirthday or later if you want to restore from seed, NOT a zero timestamp.
// A timestamp less than MinBirthday is not considered valid and will not trigger
// a rescan.
func Birthday(birthday time.Time) Option {
	return func(cfg *config) error {
		cfg.birthday = birthday
		return nil
	}
}

// Logger sets a logger for the wallet if desired.
func Logger(logger *logger.Logger) Option {
	return func(cfg *config) error {
		cfg.logger = logger
		return nil
	}
}

type config struct {
	datastore   repo.Datastore
	prover      zk.Prover
	params      *params.NetworkParams
	feePerKB    types.Amount
	chainClient BlockchainClient
	logger      *logger.Logger
	dataDir     string
	mnemonic    string
	birthday    time.Time
}

func (c *config) validate() error {
	if c.params == nil {
		return errors.New("params cannot be nil")
	}
	if c.prover == nil {
		return errors.New("prover cannot be nil")
	}
	if c.dataDir == "" {
		return errors.New("dataDir cannot be empty")
	}
	if c.chainClient == nil {
		return errors.New("BlockchainClient cannot be nil")
	}
	return nil
}
