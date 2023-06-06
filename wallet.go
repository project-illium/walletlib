// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	badger "github.com/ipfs/go-ds-badger"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
)

type Wallet struct {
	ds     repo.Datastore
	params *params.NetworkParams
}

func NewWallet(opts ...Option) (*Wallet, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ds := cfg.datastore
	var err error
	if cfg.datastore == nil {
		ds, err = badger.NewDatastore(cfg.dataDir, &badger.DefaultOptions)
		if err != nil {
			return nil, err
		}
	}

	return &Wallet{
		ds:     ds,
		params: cfg.params,
	}, nil
}

func (w *Wallet) Close() {
	w.ds.Close()
}
