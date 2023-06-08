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
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"google.golang.org/protobuf/proto"
	"strconv"
	"sync"
	"time"
)

const MnemonicEntropyBits = 256

type Wallet struct {
	ds              repo.Datastore
	params          *params.NetworkParams
	keychain        *Keychain
	nullifiers      map[types.Nullifier]types.ID
	feePerKB        types.Amount
	fetchProofsFunc ProofsSource
	broadcastFunc   BroadcastFunc

	mtx sync.RWMutex
}

type BroadcastFunc func(tx *transactions.Transaction) error

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

	fpkb := types.Amount(repo.DefaultFeePerKilobyte)
	if cfg.feePerKB != 0 {
		fpkb = cfg.feePerKB
	}

	return &Wallet{
		ds:              ds,
		params:          cfg.params,
		keychain:        keychain,
		nullifiers:      make(map[types.Nullifier]types.ID),
		feePerKB:        fpkb,
		broadcastFunc:   cfg.broadcastFunc,
		fetchProofsFunc: cfg.fetchProofsFunc,
		mtx:             sync.RWMutex{},
	}, nil
}

func (w *Wallet) ConnectBlock(blk *blocks.Block, matches map[types.ID]*blockchain.ScanMatch) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	for _, tx := range blk.Transactions {
		var (
			isOurs    bool
			walletOut types.Amount
			walletIn  types.Amount
		)
		for _, n := range tx.Nullifiers() {
			if commitment, ok := w.nullifiers[n]; ok {
				b, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
				if err != nil {
					// TODO: log err
					continue
				}
				var note pb.SpendNote
				if err := proto.Unmarshal(b, &note); err != nil {
					// TODO: log err
					continue
				}
				walletOut += types.Amount(note.Amount)
				if err := w.ds.Delete(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String())); err != nil {
					// TODO: log err
					continue
				}
				if err := w.ds.Delete(context.Background(), datastore.NewKey(NullifierKeyPrefix+n.String())); err != nil {
					// TODO: log err
					continue
				}
				delete(w.nullifiers, n)
			}
			isOurs = true
		}
		for _, out := range tx.Outputs() {
			if match, ok := matches[types.NewID(out.Commitment)]; ok {
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
				spendPub, err := w.ds.Get(context.Background(), datastore.NewKey(SpendPubkeyDatastoreKeyPrefix+strconv.Itoa(int(keyIndex))))
				if err != nil {
					// TODO: log error
					continue
				}
				dbNote := &pb.SpendNote{
					Commitment:  out.Commitment,
					KeyIndex:    keyIndex,
					ScriptHash:  note.ScriptHash,
					Amount:      uint64(note.Amount),
					Asset_ID:    note.AssetID[:],
					State:       note.State[:],
					Salt:        note.Salt[:],
					SpendPubkey: spendPub,
					AccIndex:    match.AccIndex,
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
				nullifier, err := types.CalculateNullifier(match.AccIndex, note.Salt, mockBasicUnlockScriptCommitment, spendPub)
				if err != nil {
					// TODO: log error
					continue
				}
				if err := w.ds.Put(context.Background(), datastore.NewKey(NullifierKeyPrefix+nullifier.String()), out.Commitment); err != nil {
					// TODO: log error
					continue
				}
				w.nullifiers[nullifier] = types.NewID(out.Commitment)
				walletIn += note.Amount
				isOurs = true
			}
		}

		if isOurs {
			txid := tx.ID()
			wtx := &pb.WalletTransaction{
				Txid:   txid[:],
				AmtIn:  uint64(walletIn),
				AmtOut: uint64(walletOut),
			}
			ser, err := proto.Marshal(wtx)
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

func (w *Wallet) MnemonicSeed() (string, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

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

func (w *Wallet) GetTransactions() ([]*WalletTransaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: TransactionDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	txs := make([]*WalletTransaction, 0, 5)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var wtx pb.WalletTransaction
		if err := proto.Unmarshal(result.Value, &wtx); err != nil {
			return nil, err
		}
		txs = append(txs, &WalletTransaction{
			Txid:      types.NewID(wtx.Txid),
			AmountIn:  types.Amount(wtx.AmtIn),
			AmountOut: types.Amount(wtx.AmtOut),
		})
	}
	return txs, nil
}

func (w *Wallet) ViewKeys() []*crypto.Curve25519PrivateKey {
	idks := w.keychain.getViewKeys()
	keys := make([]*crypto.Curve25519PrivateKey, 0, len(idks))
	for _, k := range idks {
		keys = append(keys, k.key)
	}
	return keys
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

func (w *Wallet) Spend(toAddr Address, amount types.Amount, feePerKB types.Amount) (types.ID, error) {
	tx, err := w.buildAndProveTransaction(toAddr, amount, feePerKB)
	if err != nil {
		return types.ID{}, nil
	}
	if err := w.broadcastFunc(tx); err != nil {
		return types.ID{}, nil
	}
	return tx.ID(), nil
}

func (w *Wallet) Close() {
	w.ds.Close()
}

type WalletTransaction struct {
	Txid      types.ID
	AmountIn  types.Amount
	AmountOut types.Amount
}
