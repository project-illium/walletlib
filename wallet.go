// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	badger "github.com/ipfs/go-ds-badger"
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/repo/mock"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MnemonicEntropyBits = 256

type Wallet struct {
	ds            repo.Datastore
	params        *params.NetworkParams
	keychain      *Keychain
	nullifiers    map[types.Nullifier]types.ID
	scanner       *TransactionScanner
	accdb         *blockchain.AccumulatorDB
	feePerKB      types.Amount
	broadcastFunc BroadcastFunc
	getBlocksFunc GetBlockFunc
	getAccFunc    GetAccumulatorCheckpointFunc
	chainHeight   uint32
	rescan        uint32
	newWallet     bool

	mtx sync.RWMutex
}

type BroadcastFunc func(tx *transactions.Transaction) error
type GetBlockFunc func(height uint32) (*blocks.Block, error)
type GetAccumulatorCheckpointFunc func(height uint32) (*blockchain.Accumulator, uint32, error)

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

	results, err := ds.Query(context.Background(), query.Query{
		Prefix: NullifierKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	nullifiers := make(map[types.Nullifier]types.ID)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		s := strings.Split(result.Key, "/")
		n, err := types.NewNullifierFromString(s[len(s)-1])
		if err != nil {
			return nil, err
		}
		nullifiers[n] = types.NewID(result.Value)
	}

	fpkb := types.Amount(repo.DefaultFeePerKilobyte)
	if cfg.feePerKB != 0 {
		fpkb = cfg.feePerKB
	}

	var (
		height    uint32
		newWallet bool
	)
	heightBytes, err := ds.Get(context.Background(), datastore.NewKey(WalletHeightDatastoreKey))
	if err != nil && !errors.Is(err, datastore.ErrNotFound) {
		return nil, err
	} else if errors.Is(err, datastore.ErrNotFound) {
		newWallet = true
	} else if err == nil {
		height = binary.BigEndian.Uint32(heightBytes)
	}

	adb := blockchain.NewAccumulatorDB(ds)
	if !newWallet {
		if err := adb.Init(nil); err != nil {
			return nil, err
		}
	}

	viewKeys, err := keychain.getViewKeys()
	if err != nil {
		return nil, err
	}

	if cfg.logger != nil {
		log = cfg.logger
	} else {
		log = zap.S()
	}

	return &Wallet{
		ds:            ds,
		params:        cfg.params,
		keychain:      keychain,
		nullifiers:    nullifiers,
		feePerKB:      fpkb,
		broadcastFunc: cfg.broadcastFunc,
		getBlocksFunc: cfg.getBlockFunc,
		getAccFunc:    cfg.getAccFunc,
		accdb:         adb,
		chainHeight:   height,
		scanner:       NewTransactionScanner(viewKeys...),
		newWallet:     newWallet,
		mtx:           sync.RWMutex{},
	}, nil
}

func (w *Wallet) Start() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	log.Info("Wallet started. Syncing blocks to tip...")

	if w.newWallet {
		genesis, err := w.getBlocksFunc(0)
		if err != nil {
			log.Errorf("Wallet error fetching genesis block: %s", err)
		}
		w.connectBlock(genesis, w.scanner, w.accdb, false)
	}

	for {
		height := w.chainHeight + 1
		blk, err := w.getBlocksFunc(height)
		if err != nil {
			break
		}
		w.connectBlock(blk, w.scanner, w.accdb, false)
		if height%10000 == 0 {
			log.Debugf("Wallet synced to height %d", height)
		}
	}
	log.Info("Wallet sync complete.")
}

func (w *Wallet) ConnectBlock(blk *blocks.Block) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	w.connectBlock(blk, w.scanner, w.accdb, false)
}

func (w *Wallet) rescanWallet(fromHeight uint32, keys ...*crypto.Curve25519PrivateKey) error {
	if atomic.SwapUint32(&w.rescan, 1) != 0 {
		return errors.New("rescan already running")
	}

	viewKeys, err := w.ViewKeys()
	if err != nil {
		log.Errorf("Error loading view keys during rescan: %s", err)
	}

	scanner := NewTransactionScanner(append(viewKeys, keys...)...)
	accdb := blockchain.NewAccumulatorDB(mock.NewMapDatastore())

	checkpoint, height, err := w.getAccFunc(fromHeight)
	if err != nil && !errors.Is(err, blockchain.ErrNoCheckpoint) {
		return err
	} else if err == nil {
		if err := accdb.Commit(checkpoint, height, blockchain.FlushNop); err != nil {
			return err
		}
	}
	if height == 0 {
		w.connectBlock(w.params.GenesisBlock, scanner, accdb, true)
	}

	getHeight := height + 1
	log.Debugf("Wallet rescan started at height: %d", getHeight)
	for {
		blk, err := w.getBlocksFunc(getHeight)
		if err != nil {
			break
		}

		w.mtx.Lock()
		w.connectBlock(blk, scanner, accdb, true)
		if getHeight%10000 == 0 {
			log.Debugf("Wallet rescanned to height %d", getHeight)
		}

		if getHeight == w.chainHeight {
			if err := w.accdb.Commit(accdb.Accumulator(), w.chainHeight, blockchain.FlushRequired); err != nil {
				return err
			}
			atomic.SwapUint32(&w.rescan, 0)
			w.mtx.Unlock()
			log.Debugf("Wallet rescan complete")
			return nil
		}
		getHeight++
		w.mtx.Unlock()
	}
	return nil
}

func (w *Wallet) connectBlock(blk *blocks.Block, scanner *TransactionScanner, accdb *blockchain.AccumulatorDB, isRescan bool) {
	matches := scanner.ScanOutputs(blk)
	accumulator := accdb.Accumulator()

	matchedTxs := 0
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
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				var note pb.SpendNote
				if err := proto.Unmarshal(b, &note); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				walletOut += types.Amount(note.Amount)
				if err := w.ds.Delete(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String())); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				if err := w.ds.Delete(context.Background(), datastore.NewKey(NullifierKeyPrefix+n.String())); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				delete(w.nullifiers, n)
				isOurs = true
				accumulator.DropProof(commitment.Bytes())
				log.Debugf("Wallet detected spend of nullifier %s in block %d", n.String(), blk.Header.Height)
			}
		}
		for _, out := range tx.Outputs() {
			if match, ok := matches[types.NewID(out.Commitment)]; ok {
				accumulator.Insert(out.Commitment, true)
				commitmentIndex := accumulator.NumElements() - 1

				addrInfo, err := w.keychain.addrInfo(match.Key)
				if err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}

				note := types.SpendNote{}
				if err := note.Deserialize(match.DecryptedNote); err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				if !bytes.Equal(hash.HashFunc(match.DecryptedNote), out.Commitment) {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: decrypted note hash does not match commitment")
					continue
				}
				if note.AssetID.Compare(types.IlliumCoinID) != 0 {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: note assetID is not illium coinID")
					continue
				}
				if note.Amount == 0 {
					accumulator.DropProof(out.Commitment)
					log.Error("Wallet connect block error: note amount is zero. Block height: %d: Addr: %s", blk.Header.Height, addrInfo.Addr)
					continue
				}

				dbNote := &pb.SpendNote{
					Address:    addrInfo.Addr,
					Commitment: out.Commitment,
					KeyIndex:   addrInfo.KeyIndex,
					ScriptHash: note.ScriptHash,
					Amount:     uint64(note.Amount),
					Asset_ID:   note.AssetID[:],
					State:      note.State[:],
					Salt:       note.Salt[:],
					AccIndex:   commitmentIndex,
					WatchOnly:  addrInfo.WatchOnly,
					UnlockingScript: &pb.UnlockingScript{
						ScriptCommitment: addrInfo.UnlockingScript.ScriptCommitment,
						ScriptParams:     addrInfo.UnlockingScript.ScriptParams,
					},
				}
				ser, err := proto.Marshal(dbNote)
				if err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				if err := w.ds.Put(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(out.Commitment)), ser); err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				nullifier, err := types.CalculateNullifier(commitmentIndex, note.Salt, addrInfo.UnlockingScript.ScriptCommitment, addrInfo.UnlockingScript.ScriptParams...)
				if err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				if err := w.ds.Put(context.Background(), datastore.NewKey(NullifierKeyPrefix+nullifier.String()), out.Commitment); err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				w.nullifiers[nullifier] = types.NewID(out.Commitment)
				walletIn += note.Amount
				isOurs = true
				log.Debugf("Wallet detected incoming output %s. Txid: %s in block %d", types.NewID(out.Commitment), tx.ID(), blk.Header.Height)
			} else {
				accumulator.Insert(out.Commitment, false)
			}
		}

		stakeTx := tx.GetStakeTransaction()
		if stakeTx != nil {
			commitment, ok := w.nullifiers[types.NewNullifier(stakeTx.Nullifier)]
			if ok {
				b, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
				if err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				var note pb.SpendNote
				if err := proto.Unmarshal(b, &note); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				note.Staked = true

				ser, err := proto.Marshal(&note)
				if err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				if err := w.ds.Put(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()), ser); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				log.Debugf("Wallet detected stake tx. Txid: %s in block %d", tx.ID(), blk.Header.Height)
			}
		}

		flushMode := blockchain.FlushPeriodic
		if isOurs {
			flushMode = blockchain.FlushRequired
		}
		if err := accdb.Commit(accumulator, blk.Header.Height, flushMode); err != nil {
			log.Errorf("Wallet connect block error: %s", err)
		}
		if !isRescan {
			w.chainHeight = blk.Header.Height
		}

		if isOurs {
			matchedTxs++
			txid := tx.ID()
			wtx := &pb.WalletTransaction{
				Txid:   txid[:],
				AmtIn:  uint64(walletIn),
				AmtOut: uint64(walletOut),
			}
			ser, err := proto.Marshal(wtx)
			if err != nil {
				log.Errorf("Wallet connect block error: %s", err)
				continue
			}
			if err := w.ds.Put(context.Background(), datastore.NewKey(TransactionDatastoreKeyPrefix+tx.ID().String()), ser); err != nil {
				log.Errorf("Wallet connect block error: %s", err)
				continue
			}

			if !isRescan {
				heightBytes := make([]byte, 32)
				binary.BigEndian.PutUint32(heightBytes, w.chainHeight)
				if err := w.ds.Put(context.Background(), datastore.NewKey(WalletHeightDatastoreKey), heightBytes); err != nil {
					log.Errorf("Wallet connect block error: %s", err)
				}
			}
			direction := "incoming"
			amtStr := fmt.Sprintf("+%d", walletIn-walletOut)
			if walletOut > walletIn {
				direction = "outgoing"
				amtStr = fmt.Sprintf("-%d", walletOut-walletIn)
			}
			log.Infof("New %s wallet transaction. Txid: %s, Coins: %s", direction, tx.ID(), amtStr)
		}
	}
	log.Debugf("Wallet processed block at height %d. Matched txs: %d", blk.Header.Height, matchedTxs)
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

func (w *Wallet) AddressInfo(addr Address) (*pb.AddrInfo, error) {
	ser, err := w.ds.Get(context.Background(), datastore.NewKey(AddressDatastoreKeyPrefix+addr.String()))
	if err != nil {
		return nil, err
	}

	var addrInfo pb.AddrInfo
	if err := proto.Unmarshal(ser, &addrInfo); err != nil {
		return nil, err
	}
	return &addrInfo, nil
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

func (w *Wallet) Notes() ([]*pb.SpendNote, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: NotesDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	notes := make([]*pb.SpendNote, 0, 5)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var note pb.SpendNote
		if err := proto.Unmarshal(result.Value, &note); err != nil {
			return nil, err
		}
		notes = append(notes, &note)
	}
	return notes, nil
}

func (w *Wallet) Transactions() ([]*WalletTransaction, error) {
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

func (w *Wallet) ViewKeys() ([]*crypto.Curve25519PrivateKey, error) {
	return w.keychain.getViewKeys()
}

func (w *Wallet) PrivateKeys() (map[WalletPrivateKey]Address, error) {
	return w.keychain.PrivateKeys()
}

func (w *Wallet) PrunePrivateKeys() error {
	return w.keychain.Prune()
}

func (w *Wallet) NetworkKey() (lcrypto.PrivKey, error) {
	return w.keychain.NetworkKey()
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

func (w *Wallet) Spend(toAddr Address, amount types.Amount, feePerKB types.Amount, inputCommitments ...types.ID) (types.ID, error) {
	tx, err := w.buildAndProveTransaction(toAddr, amount, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.broadcastFunc(tx); err != nil {
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) SweepWallet(toAddr Address, feePerKB types.Amount) (types.ID, error) {
	tx, err := w.sweepAndProveTransaction(toAddr, feePerKB)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.broadcastFunc(tx); err != nil {
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) Stake(commitments []types.ID) error {
	for _, commitment := range commitments {
		tx, err := w.buildAndProveStakeTransaction(commitment)
		if err != nil {
			return err
		}
		if err := w.broadcastFunc(tx); err != nil {
			return err
		}
	}
	return nil
}

func (w *Wallet) ImportAddress(addr Address, unlockingScript types.UnlockingScript, viewPrivkey lcrypto.PrivKey, rescan bool, rescanHeight uint32) error {
	if unlockingScript.Hash() != addr.ScriptHash() {
		return errors.New("unlocking script does not match address")
	}
	if !viewPrivkey.GetPublic().Equals(addr.ViewKey()) {
		return errors.New("view key does not match address")
	}
	curveKey, ok := viewPrivkey.(*crypto.Curve25519PrivateKey)
	if !ok {
		return errors.New("view key is not curve25519")
	}

	if rescan && atomic.LoadUint32(&w.rescan) != 0 {
		return errors.New("rescan already running")
	}

	if err := w.keychain.ImportAddress(addr, unlockingScript, viewPrivkey); err != nil {
		return err
	}
	if rescan {
		go func() {
			if rescanHeight > 0 {
				rescanHeight = rescanHeight - 1
			}
			if err := w.rescanWallet(rescanHeight, curveKey); err != nil {
				log.Errorf("rescan wallet error: %s", err)
			}
		}()
	}
	return nil
}

func (w *Wallet) GetInclusionProofs(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error) {
	acc := w.accdb.Accumulator()

	proofs := make([]*blockchain.InclusionProof, 0, len(commitments))
	for _, commitment := range commitments {
		proof, err := acc.GetProof(commitment[:])
		if err != nil {
			return nil, types.ID{}, fmt.Errorf("err fetching inclusion proof: %s", err)
		}
		proofs = append(proofs, proof)
	}
	return proofs, acc.Root(), nil
}

func (w *Wallet) Close() {
	heightBytes := make([]byte, 32)
	binary.BigEndian.PutUint32(heightBytes, w.chainHeight)
	if err := w.ds.Put(context.Background(), datastore.NewKey(WalletHeightDatastoreKey), heightBytes); err != nil {
		log.Errorf("wallet close error: %s", err)
	}

	if err := w.accdb.Flush(blockchain.FlushRequired, w.chainHeight); err != nil {
		log.Errorf("wallet close error: %s", err)
	}
	if err := w.ds.Close(); err != nil {
		log.Errorf("wallet close error: %s", err)
	}
}

type WalletTransaction struct {
	Txid      types.ID
	AmountIn  types.Amount
	AmountOut types.Amount
}
