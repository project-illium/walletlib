// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/ipfs/go-datastore"
	badger "github.com/ipfs/go-ds-badger"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"google.golang.org/protobuf/proto"
)

const MnemonicEntropyBits = 256

type Wallet struct {
	ds       repo.Datastore
	params   *params.NetworkParams
	keychain *Keychain
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

	keychain, err := LoadKeychain(ds, cfg.params)
	if errors.Is(err, ErrUninitializedKeychain) {
		var mnemonic string
		if cfg.mnemonic != "" {
			mnemonic = cfg.mnemonic
		} else {
			ent, err := bip39.NewEntropy(MnemonicEntropyBits)
			if err != nil {
				return nil, err
			}
			mnemonic, err = bip39.NewMnemonic(ent)
			if err != nil {
				return nil, err
			}
		}
		keychain, err = NewKeychain(ds, cfg.params, mnemonic)
		if err != nil {
			return nil, err
		}
	}

	return &Wallet{
		ds:       ds,
		params:   cfg.params,
		keychain: keychain,
	}, nil
}

func (w *Wallet) HandleIncomingBlock(blk *blocks.Block) {
	for _, tx := range blk.Transactions {
		matches := false
		for _, out := range tx.Outputs() {
			for _, idk := range w.keychain.getViewKeys() {
				plaintext, err := idk.key.Decrypt(out.Ciphertext)
				if err == nil {
					note := types.SpendNote{}
					if err := note.Deserialize(plaintext); err != nil {
						// TODO: log error
						continue
					}
					if !bytes.Equal(hash.HashFunc(plaintext), out.Commitment) {
						// TODO: log error
						continue
					}
					if note.AssetID.Compare(types.IlliumCoinID) != 0 {
						// TODO: log error
						continue
					}
					if note.Amount == 0 {
						// TODO: log error
						continue
					}
					matches = true
					dbNote := &pb.Utxo{
						Commitment: out.Commitment,
						KeyIndex:   idk.index,
						ScriptHash: note.ScriptHash,
						Amount:     uint64(note.Amount),
						Asset_ID:   note.AssetID[:],
						State:      note.State[:],
						Salt:       note.Salt[:],

						// TODO: look up inclusion proof and put it here
					}
					ser, err := proto.Marshal(dbNote)
					if err != nil {
						// TODO: log error
						continue
					}
					if err := w.ds.Put(context.Background(), datastore.NewKey(UtxoDatastoreKeyPrefix+hex.EncodeToString(out.Commitment)), ser); err != nil {
						// TODO: log error
						continue
					}
					break
				}
			}
		}
		if matches {
			ser, err := proto.Marshal(tx)
			if err != nil {
				// TODO: log error
				continue
			}
			if err := w.ds.Put(context.Background(), datastore.NewKey(TransactionDatastoreKeyPrefix+tx.ID().String()), ser); err != nil {
				// TODO: log error
				continue
			}
		}
	}
}

func (w *Wallet) Address() (Address, error) {
	return w.keychain.Address()
}

func (w *Wallet) NewAddress() (Address, error) {
	return w.keychain.NewAddress()
}

func (w *Wallet) Close() {
	w.ds.Close()
}
