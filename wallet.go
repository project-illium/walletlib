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
	"github.com/project-illium/walletlib/pb"
	"github.com/tyler-smith/go-bip39"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MnemonicEntropyBits = 256
	maxBatchSize        = 2000
	MinBirthday         = 1694974911
)

type Wallet struct {
	ds          repo.Datastore
	params      *params.NetworkParams
	keychain    *Keychain
	nullifiers  map[types.Nullifier]types.ID
	scanner     *TransactionScanner
	accdb       *blockchain.AccumulatorDB
	feePerKB    types.Amount
	chainClient BlockchainClient
	chainHeight uint32
	rescan      uint32
	newWallet   bool
	birthday    time.Time

	done chan struct{}
	mtx  sync.RWMutex
}

func NewWallet(opts ...Option) (*Wallet, error) {
	var cfg config
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
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
		ds:          ds,
		params:      cfg.params,
		keychain:    keychain,
		nullifiers:  nullifiers,
		feePerKB:    fpkb,
		chainClient: cfg.chainClient,
		accdb:       adb,
		chainHeight: height,
		scanner:     NewTransactionScanner(viewKeys...),
		newWallet:   newWallet,
		birthday:    cfg.birthday,
		done:        make(chan struct{}),
		mtx:         sync.RWMutex{},
	}, nil
}

func (w *Wallet) Start() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	log.Info("Wallet started. Syncing blocks to tip...")

	if !w.chainClient.IsFullClient() {
		key, unlockingScript, err := w.registrationParams()
		if err != nil {
			log.Errorf("Error loading registration parameters: %s", err)
		} else {
			birthday := int64(0)
			if !w.birthday.Before(time.Unix(MinBirthday, 0)) {
				birthday = w.birthday.Unix()
			}
			if err := w.chainClient.Register(key, unlockingScript, birthday); err != nil {
				log.Errorf("Error registering lite client with server: %s", err)
			}
		}
	}

	if w.newWallet {
		w.connectBlock(w.params.GenesisBlock, w.scanner, w.accdb, false)
	}

	for {
		from := w.chainHeight + 1
		blks, err := w.chainClient.GetBlocks(from, from+maxBatchSize)
		if err != nil {
			break
		}
		for _, blk := range blks {
			w.connectBlock(blk, w.scanner, w.accdb, false)
			if blk.Header.Height%10000 == 0 {
				log.Debugf("Wallet synced to height %d", blk.Header.Height)
			}
		}

		if !w.chainClient.IsFullClient() {
			break
		}
	}

	go func() {
		ch, err := w.chainClient.SubscribeBlocks()
		if err != nil {
			log.Errorf("Error subscribing to chain client: %s", err)
			return
		}

	loop:
		for {
			select {
			case <-w.done:
				return
			case blk := <-ch:
				if blk == nil {
					continue
				}
				w.mtx.Lock()
				if blk.Header.Height > w.chainHeight+1 && w.chainClient.IsFullClient() {
					for {
						from := w.chainHeight + 1
						blks, err := w.chainClient.GetBlocks(from, blk.Header.Height-1)
						if err != nil {
							log.Errorf("Error fetching blocks from chain client: %s", err)
							continue loop
						}
						for _, b := range blks {
							w.connectBlock(b, w.scanner, w.accdb, false)
						}

						if w.chainHeight == blk.Header.Height-1 {
							break
						}
					}
				}
				w.connectBlock(blk, w.scanner, w.accdb, false)
				w.mtx.Unlock()
			}
		}
	}()

	log.Info("Wallet sync complete.")
}

func (w *Wallet) ConnectBlock(blk *blocks.Block) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	w.connectBlock(blk, w.scanner, w.accdb, false)
}

func (w *Wallet) rescanWallet(fromHeight uint32) error {
	if atomic.SwapUint32(&w.rescan, 1) != 0 {
		return errors.New("rescan already running")
	}

	viewKeys, err := w.ViewKeys()
	if err != nil {
		log.Errorf("Error loading view keys during rescan: %s", err)
	}

	scanner := NewTransactionScanner(viewKeys...)
	accdb := blockchain.NewAccumulatorDB(mock.NewMapDatastore())

	var (
		height     uint32 = 0
		checkpoint *blockchain.Accumulator
	)

	if w.chainClient.IsFullClient() {
		checkpoint, height, err = w.chainClient.GetAccumulatorCheckpoint(fromHeight)
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
	}

	getHeight := height + 1
	log.Debugf("Wallet rescan started at height: %d", getHeight)
	for {
		blks, err := w.chainClient.GetBlocks(getHeight, getHeight+maxBatchSize)
		if err != nil {
			break
		}

		w.mtx.Lock()
		for _, blk := range blks {
			w.connectBlock(blk, scanner, accdb, true)
			if blk.Header.Height%10000 == 0 {
				log.Debugf("Wallet rescanned to height %d", getHeight)
			}
			if !w.chainClient.IsFullClient() {
				w.mtx.Unlock()
				break
			}

			if blk.Header.Height == w.chainHeight {
				if err := w.accdb.Commit(accdb.Accumulator(), w.chainHeight, blockchain.FlushRequired); err != nil {
					return err
				}
				atomic.SwapUint32(&w.rescan, 0)
				w.mtx.Unlock()
				log.Debugf("Wallet rescan complete")
				return nil
			}
			getHeight = blk.Header.Height + 1
		}
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
			match, ok := matches[types.NewID(out.Commitment)]
			if w.chainClient.IsFullClient() {
				accumulator.Insert(out.Commitment, ok)
			}
			if ok {
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

				locktime := int64(0)
				if note.State != [128]byte{} {
					script := types.UnlockingScript{
						ScriptCommitment: MockTimelockedMultisigScriptCommitment,
						ScriptParams: [][]byte{
							{0x01},
							note.State[:8],
							addrInfo.UnlockingScript.ScriptParams[0],
						},
					}
					scriptHash := script.Hash()

					if bytes.Equal(note.ScriptHash, scriptHash[:]) {
						locktime = int64(binary.BigEndian.Uint64(note.State[:8]))

						priv, err := lcrypto.UnmarshalPrivateKey(addrInfo.ViewPrivKey)
						if err != nil {
							accumulator.DropProof(out.Commitment)
							log.Errorf("Err unmarshalling view key: %s", err)
							continue
						}

						addr, err := NewBasicAddress(script, priv.GetPublic(), w.params)
						if err != nil {
							accumulator.DropProof(out.Commitment)
							log.Errorf("Err creating timelocked address: %s", err)
							continue
						}
						addrInfo.Addr = addr.String()
						addrInfo.ScriptHash = scriptHash[:]
						addrInfo.UnlockingScript.ScriptCommitment = script.ScriptCommitment
						addrInfo.UnlockingScript.ScriptParams = script.ScriptParams
					}
				}

				if !bytes.Equal(note.ScriptHash, addrInfo.ScriptHash) {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: note doesn't match script hash. Block height: %d: Addr: %s", blk.Header.Height, addrInfo.Addr)
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
					LockedUntil: locktime,
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
				nullifier := types.CalculateNullifier(commitmentIndex, note.Salt, addrInfo.UnlockingScript.ScriptCommitment, addrInfo.UnlockingScript.ScriptParams...)
				if err := w.ds.Put(context.Background(), datastore.NewKey(NullifierKeyPrefix+nullifier.String()), out.Commitment); err != nil {
					accumulator.DropProof(out.Commitment)
					log.Errorf("Wallet connect block error: %s", err)
					continue
				}
				w.nullifiers[nullifier] = types.NewID(out.Commitment)
				walletIn += note.Amount
				isOurs = true
				log.Debugf("Wallet detected incoming output %s. Txid: %s in block %d", types.NewID(out.Commitment), tx.ID(), blk.Header.Height)
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
		if w.chainClient.IsFullClient() {
			if err := accdb.Commit(accumulator, blk.Header.Height, flushMode); err != nil {
				log.Errorf("Wallet connect block error: %s", err)
			}
		}
		if !isRescan && blk.Header.Height > 0 {
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

			if !isRescan && blk.Header.Height > 0 {
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

	if w.keychain.isEncrypted {
		return "", ErrEncryptedKeychain
	}

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
	if !w.chainClient.IsFullClient() {
		return nil, errors.New("lite client mode does not support the use multiple addresses")
	}
	addr, err := w.keychain.NewAddress()
	if err != nil {
		return nil, err
	}

	viewKey, err := w.keychain.ViewKey(addr)
	if err != nil {
		return nil, err
	}

	curveKey, ok := viewKey.(*crypto.Curve25519PrivateKey)
	if !ok {
		return nil, errors.New("view key is not curve25519")
	}

	w.mtx.Lock()
	w.scanner.AddKeys(curveKey)
	w.mtx.Unlock()

	return addr, nil
}

func (w *Wallet) TimelockedAddress(lockUntil time.Time) (Address, error) {
	return w.keychain.TimelockedAddress(lockUntil)
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
	tx, err := w.buildAndProveTransaction(toAddr, [128]byte{}, amount, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) SweepWallet(toAddr Address, feePerKB types.Amount) (types.ID, error) {
	tx, err := w.sweepAndProveTransaction(toAddr, feePerKB)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) TimelockCoins(amount types.Amount, lockUntil time.Time, feePerKB types.Amount, inputCommitments ...types.ID) (types.ID, error) {
	addr, err := w.keychain.TimelockedAddress(lockUntil)
	if err != nil {
		return types.ID{}, err
	}
	var locktime [128]byte
	binary.BigEndian.PutUint64(locktime[:8], uint64(lockUntil.Unix()))

	tx, err := w.buildAndProveTransaction(addr, locktime, amount, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
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
		if err := w.chainClient.Broadcast(tx); err != nil {
			return err
		}
	}
	return nil
}

func (w *Wallet) ImportAddress(addr Address, unlockingScript types.UnlockingScript, viewPrivkey lcrypto.PrivKey, rescan bool, rescanHeight uint32) error {
	if !w.chainClient.IsFullClient() {
		return errors.New("lite client mode does not support address importing")
	}

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

	//FIXME: make sure view key not already in use.

	w.mtx.Lock()
	w.scanner.AddKeys(curveKey)
	w.mtx.Unlock()

	if rescan {
		go func() {
			if rescanHeight > 0 {
				rescanHeight = rescanHeight - 1
			}
			if err := w.rescanWallet(rescanHeight); err != nil {
				log.Errorf("rescan wallet error: %s", err)
			}
		}()
	}
	return nil
}

func (w *Wallet) GetInclusionProofs(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error) {
	if w.chainClient.IsFullClient() {
		proofs := make([]*blockchain.InclusionProof, 0, len(commitments))
		acc := w.accdb.Accumulator()
		for _, commitment := range commitments {
			proof, err := acc.GetProof(commitment[:])
			if err != nil {
				return nil, types.ID{}, fmt.Errorf("err fetching inclusion proof: %s", err)
			}
			proofs = append(proofs, proof)
		}
		return proofs, acc.Root(), nil
	} else {
		return w.chainClient.GetInclusionProofs(commitments...)
	}
}

func (w *Wallet) Close() {
	close(w.done)
	w.chainClient.Close()

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

func (w *Wallet) registrationParams() (*crypto.Curve25519PrivateKey, types.UnlockingScript, error) {
	addr, err := w.keychain.Address()
	if err != nil {
		return nil, types.UnlockingScript{}, err
	}
	addrInfo, err := w.keychain.AddrInfo(addr)
	if err != nil {
		return nil, types.UnlockingScript{}, err
	}
	viewKey, err := lcrypto.UnmarshalPrivateKey(addrInfo.ViewPrivKey)
	if err != nil {
		return nil, types.UnlockingScript{}, err
	}
	curveKey, ok := viewKey.(*crypto.Curve25519PrivateKey)
	if !ok {
		return nil, types.UnlockingScript{}, errors.New("invalid key type")
	}
	ul := types.UnlockingScript{
		ScriptCommitment: addrInfo.UnlockingScript.ScriptCommitment,
		ScriptParams:     addrInfo.UnlockingScript.ScriptParams,
	}
	return curveKey, ul, nil
}

type WalletTransaction struct {
	Txid      types.ID
	AmountIn  types.Amount
	AmountOut types.Amount
}
