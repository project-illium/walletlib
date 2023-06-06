// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"errors"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
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

type config struct {
	datastore repo.Datastore
	params    *params.NetworkParams
	dataDir   string
}

func (c *config) validate() error {
	if c.params == nil {
		return errors.New("params cannot be nil")
	}
	if c.dataDir == "" {
		return errors.New("dataDir cannot be empty")
	}
	return nil
}
