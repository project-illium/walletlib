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
	"github.com/ipfs/go-datastore/query"
	badger "github.com/ipfs/go-ds-badger"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"google.golang.org/protobuf/proto"
	"sync"
	"time"
)

const MnemonicEntropyBits = 256

type Wallet struct {
	ds       repo.Datastore
	params   *params.NetworkParams
	keychain *Keychain

	mtx sync.RWMutex
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
		mtx:      sync.RWMutex{},
	}, nil
}

func (w *Wallet) handleMatches(matches map[types.ID]*blockchain.ScanMatch) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	txMap := make(map[types.ID]*transactions.Transaction)
	for _, match := range matches {
		outputs := match.Transaction.Outputs()
		if match.OutputIndex >= len(outputs) {
			// TODO: log error
			continue
		}
		out := outputs[match.OutputIndex]

		var (
			keyFound = false
			keyIndex = uint32(0)
		)
		for _, k := range w.keychain.getViewKeys() {
			if k.key.Equals(match.Key) {
				keyFound = true
				keyIndex = k.index
				break
			}
		}
		if !keyFound {
			// TODO: log error
			continue
		}

		note := types.SpendNote{}
		if err := note.Deserialize(match.DecryptedNote); err != nil {
			// TODO: log error
			continue
		}
		if !bytes.Equal(hash.HashFunc(match.DecryptedNote), out.Commitment) {
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
		dbNote := &pb.SpendNote{
			Commitment: out.Commitment,
			KeyIndex:   keyIndex,
			ScriptHash: note.ScriptHash,
			Amount:     uint64(note.Amount),
			Asset_ID:   note.AssetID[:],
			State:      note.State[:],
			Salt:       note.Salt[:],
		}
		ser, err := proto.Marshal(dbNote)
		if err != nil {
			// TODO: log error
			continue
		}
		if err := w.ds.Put(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(out.Commitment)), ser); err != nil {
			// TODO: log error
			continue
		}
		txMap[match.Transaction.ID()] = match.Transaction
	}

	for _, tx := range txMap {
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

func (w *Wallet) MnemonicSeed() (string, error) {
	mnemonic, err := w.ds.Get(context.Background(), datastore.NewKey(MnemonicSeedDatastoreKey))
	if err != nil {
		return "", err
	}
	if string(mnemonic) == "" {
		return "", ErrPublicOnlyKeychain
	}
	return string(mnemonic), nil
}

func (w *Wallet) Address() (Address, error) {
	return w.keychain.Address()
}

func (w *Wallet) NewAddress() (Address, error) {
	return w.keychain.NewAddress()
}

func (w *Wallet) Addresses() ([]Address, error) {
	return w.keychain.Addresses()
}

func (w *Wallet) Balance() (types.Amount, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: NotesDatastoreKeyPrefix,
	})
	if err != nil {
		return 0, err
	}
	amt := types.Amount(0)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var note pb.SpendNote
		if err := proto.Unmarshal(result.Value, &note); err != nil {
			return 0, err
		}
		amt += types.Amount(note.Amount)
	}
	return amt, nil
}

func (w *Wallet) Notes() ([]types.SpendNote, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: NotesDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	notes := make([]types.SpendNote, 0, 5)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var note pb.SpendNote
		if err := proto.Unmarshal(result.Value, &note); err != nil {
			return nil, err
		}
		n := types.SpendNote{
			ScriptHash: note.ScriptHash,
			Amount:     types.Amount(note.Amount),
			AssetID:    types.NewID(note.Asset_ID),
		}
		copy(n.State[:], note.State)
		copy(n.Salt[:], note.Salt)
		notes = append(notes, n)
	}
	return notes, nil
}

func (w *Wallet) GetTransactions() ([]*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: TransactionDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	txs := make([]*transactions.Transaction, 0, 5)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var tx transactions.Transaction
		if err := proto.Unmarshal(result.Value, &tx); err != nil {
			return nil, err
		}
		txs = append(txs, &tx)
	}
	return txs, nil
}

func (w *Wallet) PrivateKeys() (map[WalletPrivateKey]Address, error) {
	return w.keychain.PrivateKeys()
}

func (w *Wallet) PrunePrivateKeys(passphrase string) error {
	return w.keychain.Prune(passphrase)
}

func (w *Wallet) Lock() error {
	return w.keychain.Lock()
}

func (w *Wallet) Unlock(passphrase string, duration time.Duration) error {
	return w.keychain.Unlock(passphrase, duration)
}

func (w *Wallet) SetWalletPassphrase(passphrase string) error {
	return w.keychain.SetPassphrase(passphrase)
}

func (w *Wallet) ChangeWalletPassphrase(currentPassphrase, newPassphrase string) error {
	return w.keychain.ChangePassphrase(currentPassphrase, newPassphrase)
}

func (w *Wallet) Close() {
	w.ds.Close()
}
