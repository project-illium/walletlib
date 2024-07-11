// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	ids "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/params"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/repo/datastore"
	"github.com/project-illium/ilxd/repo/mock"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/logger"
	"github.com/project-illium/walletlib/pb"
	"github.com/pterm/pterm"
	"github.com/tyler-smith/go-bip39"
	"google.golang.org/protobuf/proto"
	"math/rand"
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
	ds             datastore.Datastore
	prover         zk.Prover
	params         *params.NetworkParams
	keychain       *Keychain
	nullifiers     map[types.Nullifier]types.ID
	outputMetadata map[types.ID]*TxIO
	inflightUtxos  map[types.ID]struct{}
	scanner        *TransactionScanner
	accdb          *blockchain.AccumulatorDB
	feePerKB       types.Amount
	txSubs         map[uint64]*TransactionSubscription
	syncSubs       map[uint64]*SyncSubscription
	chainClient    BlockchainClient
	chainHeight    uint32
	rescan         uint32
	newWallet      bool
	birthday       time.Time

	done        chan struct{}
	mtx         sync.RWMutex
	txSubMtx    sync.RWMutex
	syncSubMtx  sync.RWMutex
	metadataMtx sync.RWMutex
	spendMtx    sync.RWMutex
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
		ds, err = datastore.NewIlxdDatastore(cfg.dataDir, cfg.params)
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

	adb := blockchain.NewAccumulatorDB(ds)

	var (
		height    uint32
		newWallet bool
	)
	_, err = ds.Get(context.Background(), ids.NewKey(WalletHeightDatastoreKey))
	if err != nil && !errors.Is(err, ids.ErrNotFound) {
		return nil, err
	} else if errors.Is(err, ids.ErrNotFound) {
		newWallet = true
	}

	if !newWallet {
		if err := adb.Init(nil); err != nil {
			return nil, err
		}
		height, err = adb.LastFlushHeight()
		if err != nil {
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
		log = logger.DefaultLogger.WithLevel(pterm.LogLevelInfo)
	}

	scanner := NewTransactionScanner(viewKeys...)

	publicAddr, vieKey, err := keychain.publicAddress()
	if err != nil {
		return nil, err
	}
	publicAddrLockingParams := publicAddr.ScriptHash()
	scanner.AddScriptHash(types.NewID(publicAddrLockingParams[:]), vieKey)

	return &Wallet{
		ds:             ds,
		prover:         cfg.prover,
		params:         cfg.params,
		keychain:       keychain,
		nullifiers:     nullifiers,
		outputMetadata: make(map[types.ID]*TxIO),
		inflightUtxos:  make(map[types.ID]struct{}),
		feePerKB:       fpkb,
		chainClient:    cfg.chainClient,
		accdb:          adb,
		chainHeight:    height,
		txSubs:         make(map[uint64]*TransactionSubscription),
		syncSubs:       make(map[uint64]*SyncSubscription),
		scanner:        scanner,
		newWallet:      newWallet,
		birthday:       cfg.birthday,
		done:           make(chan struct{}),
		mtx:            sync.RWMutex{},
		txSubMtx:       sync.RWMutex{},
		syncSubMtx:     sync.RWMutex{},
		metadataMtx:    sync.RWMutex{},
		spendMtx:       sync.RWMutex{},
	}, nil
}

func (w *Wallet) Start() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	log.Info("Wallet started. Syncing blocks to tip...")

	if !w.chainClient.IsFullClient() {
		key, lockingScript, err := w.registrationParams()
		if err != nil {
			log.WithCaller(true).Error("Error loading registration parameters", log.Args("error", err))
		} else {
			birthday := int64(0)
			if !w.birthday.Before(time.Unix(MinBirthday, 0)) {
				birthday = w.birthday.Unix()
			}
			if err := w.chainClient.Register(key, lockingScript, birthday); err != nil {
				log.WithCaller(true).Error("Error registering lite client with wallet server", log.Args("error", err))
			}
		}
	}

	if w.newWallet {
		w.connectBlock(w.params.GenesisBlock, w.scanner, w.accdb, false)
	}

	for {
		from := w.chainHeight + 1
		blks, bestHeight, err := w.chainClient.GetBlocks(from, from+maxBatchSize)
		if err != nil {
			break
		}
		for _, blk := range blks {
			w.connectBlock(blk, w.scanner, w.accdb, false)
			if blk.Header.Height%10000 == 0 {
				log.Debug("Wallet sync", log.Args("height", blk.Header.Height))
			}
			w.syncSubMtx.RLock()
			for _, sub := range w.syncSubs {
				go func(s *SyncSubscription) {
					s.C <- &SyncNotification{
						CurrentBlock: blk.Header.Height,
						BestBlock:    bestHeight,
					}
				}(sub)
			}
			w.syncSubMtx.RUnlock()
		}

		if !w.chainClient.IsFullClient() {
			break
		}
	}

	go func() {
		ch, err := w.chainClient.SubscribeBlocks()
		if err != nil {
			log.WithCaller(true).Error("Error subscribing to chain client", log.Args("error", err))
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
				if blk.Header.Height <= w.chainHeight {
					w.mtx.Unlock()
					continue loop
				}
				if blk.Header.Height > w.chainHeight+1 && w.chainClient.IsFullClient() {
					for {
						from := w.chainHeight + 1
						blks, _, err := w.chainClient.GetBlocks(from, blk.Header.Height-1)
						if err != nil {
							log.WithCaller(true).Error("Error fetching blocks from chain client", log.Args("error", err))
							w.mtx.Unlock()
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

	log.Info("Wallet sync complete")
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
	defer atomic.SwapUint32(&w.rescan, 0)

	viewKeys, err := w.ViewKeys()
	if err != nil {
		log.WithCaller(true).Error("Error loading view keys during rescan", log.Args("error", err))
	}

	scanner := NewTransactionScanner(viewKeys...)
	publicAddr, vieKey, err := w.keychain.publicAddress()
	if err != nil {
		log.WithCaller(true).Error("Error loading public addrs during rescan", log.Args("error", err))
	} else {
		publicAddrLockingParams := publicAddr.ScriptHash()
		scanner.AddScriptHash(types.NewID(publicAddrLockingParams[:]), vieKey)
	}

	accdb := blockchain.NewAccumulatorDB(mock.NewMockDatastore())

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
	log.Debug("Wallet rescan started", log.Args("height", getHeight))

	for {
		blks, bestHeight, err := w.chainClient.GetBlocks(getHeight, getHeight+maxBatchSize)
		if err != nil {
			break
		}

		w.mtx.Lock()
		for _, blk := range blks {
			w.connectBlock(blk, scanner, accdb, true)
			if blk.Header.Height%10000 == 0 {
				log.Debug("Wallet rescan", log.Args("height", blk.Header.Height))
			}
			if !w.chainClient.IsFullClient() {
				break
			}

			if blk.Header.Height == w.chainHeight {
				if err := w.accdb.Commit(accdb.Accumulator(), w.chainHeight, blockchain.FlushRequired); err != nil {
					w.mtx.Unlock()
					return err
				}
				w.mtx.Unlock()
				log.Debug("Wallet rescan complete")
				return nil
			}
			getHeight = blk.Header.Height + 1

			w.syncSubMtx.RLock()
			for _, sub := range w.syncSubs {
				sub.C <- &SyncNotification{
					CurrentBlock: blk.Header.Height,
					BestBlock:    bestHeight,
				}
			}
			w.syncSubMtx.RUnlock()
		}
		w.mtx.Unlock()
	}
	return nil
}

func (w *Wallet) MnemonicSeed() (string, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if w.keychain.isEncrypted {
		return "", ErrEncryptedKeychain
	}

	mnemonic, err := w.ds.Get(context.Background(), ids.NewKey(MnemonicSeedDatastoreKey))
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

func (w *Wallet) PublicAddress() (Address, error) {
	addr, key, err := w.keychain.publicAddress()
	if err != nil {
		return nil, err
	}
	sh := addr.ScriptHash()
	w.scanner.AddScriptHash(types.NewID(sh[:]), key)
	return addr, nil
}

func (w *Wallet) Addresses() ([]Address, error) {
	return w.keychain.Addresses()
}

func (w *Wallet) AddressInfo(addr Address) (*pb.AddrInfo, error) {
	ser, err := w.ds.Get(context.Background(), ids.NewKey(AddressDatastoreKeyPrefix+addr.String()))
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

func (w *Wallet) Transactions(skip, limit int) ([]*WalletTransaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: TransactionDatastoreKeyPrefix,
		Limit:  limit,
		Offset: skip,
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
		inIO, err := pbIOtoIO(wtx.Inputs, w.params)
		if err != nil {
			return nil, err
		}
		outIO, err := pbIOtoIO(wtx.Outputs, w.params)
		if err != nil {
			return nil, err
		}
		txs = append(txs, &WalletTransaction{
			Txid:      types.NewID(wtx.Txid),
			AmountIn:  types.Amount(wtx.AmtIn),
			AmountOut: types.Amount(wtx.AmtOut),
			Inputs:    inIO,
			Outputs:   outIO,
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
	tx, cleanup, err := w.buildAndProveTransaction(toAddr, types.State{}, amount, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
		cleanup()
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) SweepWallet(toAddr Address, feePerKB types.Amount, inputCommitments ...types.ID) (types.ID, error) {
	tx, cleanup, err := w.sweepAndProveTransaction(toAddr, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
		cleanup()
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) TimelockCoins(amount types.Amount, lockUntil time.Time, feePerKB types.Amount, inputCommitments ...types.ID) (types.ID, error) {
	addr, err := w.keychain.TimelockedAddress(lockUntil)
	if err != nil {
		return types.ID{}, err
	}
	locktime := make([]byte, 8)
	binary.BigEndian.PutUint64(locktime, uint64(lockUntil.Unix()))

	tx, cleanup, err := w.buildAndProveTransaction(addr, types.State{locktime}, amount, feePerKB, inputCommitments...)
	if err != nil {
		return types.ID{}, err
	}
	if err := w.chainClient.Broadcast(tx); err != nil {
		cleanup()
		return types.ID{}, err
	}
	return tx.ID(), nil
}

func (w *Wallet) Stake(commitments []types.ID) error {
	for _, commitment := range commitments {
		tx, cleanup, err := w.buildAndProveStakeTransaction(commitment)
		if err != nil {
			return err
		}
		if err := w.chainClient.Broadcast(tx); err != nil {
			cleanup()
			return err
		}
	}
	return nil
}

func (w *Wallet) ImportAddress(addr Address, lockingScript types.LockingScript, viewPrivkey lcrypto.PrivKey, rescan bool, rescanHeight uint32) error {
	if !w.chainClient.IsFullClient() {
		return errors.New("lite client mode does not support address importing")
	}

	if _, ok := addr.(*BasicAddress); !ok {
		return errors.New("public or exchange address importing is not currently supported")
	}

	scriptHash, err := lockingScript.Hash()
	if err != nil {
		return err
	}
	if scriptHash != addr.ScriptHash() {
		return errors.New("locking script does not match address")
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

	if err := w.keychain.ImportAddress(addr, lockingScript, viewPrivkey); err != nil {
		return err
	}

	w.mtx.Lock()
	w.scanner.AddKeys(curveKey)
	w.mtx.Unlock()

	if rescan {
		go func() {
			if rescanHeight > 0 {
				rescanHeight = rescanHeight - 1
			}
			if err := w.rescanWallet(rescanHeight); err != nil {
				log.WithCaller(true).Error("Error rescanning wallet", log.Args("error", err))
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

type TransactionSubscription struct {
	C     chan *WalletTransaction
	id    uint64
	Close func()
}

// SubscribeTransactions returns a subscription to the stream of wallet transactions.
func (w *Wallet) SubscribeTransactions() *TransactionSubscription {
	sub := &TransactionSubscription{
		C:  make(chan *WalletTransaction),
		id: rand.Uint64(),
	}
	sub.Close = func() {
		w.txSubMtx.Lock()
		go func() {
			for range sub.C {
			}
		}()
		close(sub.C)
		delete(w.txSubs, sub.id)
		w.txSubMtx.Unlock()
	}
	w.txSubMtx.Lock()
	w.txSubs[sub.id] = sub
	w.txSubMtx.Unlock()
	return sub
}

type SyncSubscription struct {
	C     chan *SyncNotification
	id    uint64
	Close func()
}

// SubscribeSyncNotifications returns a subscription to the stream of sync notifications.
func (w *Wallet) SubscribeSyncNotifications() *SyncSubscription {
	sub := &SyncSubscription{
		C:  make(chan *SyncNotification),
		id: rand.Uint64(),
	}
	sub.Close = func() {
		w.syncSubMtx.Lock()
		go func() {
			for range sub.C {
			}
		}()
		close(sub.C)
		delete(w.syncSubs, sub.id)
		w.syncSubMtx.Unlock()
	}
	w.syncSubMtx.Lock()
	w.syncSubs[sub.id] = sub
	w.syncSubMtx.Unlock()
	return sub
}

func (w *Wallet) Close() {
	close(w.done)
	w.chainClient.Close()

	heightBytes := make([]byte, 32)
	binary.BigEndian.PutUint32(heightBytes, w.chainHeight)
	if err := w.ds.Put(context.Background(), ids.NewKey(WalletHeightDatastoreKey), heightBytes); err != nil {
		log.WithCaller(true).Error("Wallet close error", log.Args("error", err))
	}

	if err := w.accdb.Flush(blockchain.FlushRequired, w.chainHeight); err != nil {
		log.WithCaller(true).Error("Wallet close error", log.Args("error", err))
	}
	if err := w.ds.Close(); err != nil {
		log.WithCaller(true).Error("Wallet close error", log.Args("error", err))
	}
}

func (w *Wallet) registrationParams() (*crypto.Curve25519PrivateKey, types.LockingScript, error) {
	addr, err := w.keychain.Address()
	if err != nil {
		return nil, types.LockingScript{}, err
	}
	addrInfo, err := w.keychain.AddrInfo(addr)
	if err != nil {
		return nil, types.LockingScript{}, err
	}
	viewKey, err := lcrypto.UnmarshalPrivateKey(addrInfo.ViewPrivKey)
	if err != nil {
		return nil, types.LockingScript{}, err
	}
	curveKey, ok := viewKey.(*crypto.Curve25519PrivateKey)
	if !ok {
		return nil, types.LockingScript{}, errors.New("invalid key type")
	}
	ul := types.LockingScript{
		ScriptCommitment: types.NewID(addrInfo.LockingScript.ScriptCommitment),
		LockingParams:    addrInfo.LockingScript.LockingParams,
	}
	return curveKey, ul, nil
}

type WalletTransaction struct {
	Txid      types.ID
	AmountIn  types.Amount
	AmountOut types.Amount

	Inputs  []IO
	Outputs []IO

	BlockID     types.ID
	BlockHeight uint32
}

type IO interface{}
type TxIO struct {
	Address Address
	Amount  types.Amount
}
type Unknown struct{}

func (u Unknown) MarshalJSON() ([]byte, error) {
	return json.Marshal("unknown")
}

type SyncNotification struct {
	CurrentBlock uint32
	BestBlock    uint32
}

func ioToPBio(ios []IO) []*pb.WalletTransaction_IO {
	ret := make([]*pb.WalletTransaction_IO, 0, len(ios))
	for _, io := range ios {
		switch t := io.(type) {
		case *TxIO:
			ret = append(ret, &pb.WalletTransaction_IO{
				IoType: &pb.WalletTransaction_IO_TxIo{
					TxIo: &pb.WalletTransaction_IO_TxIO{
						Address: t.Address.String(),
						Amount:  uint64(t.Amount),
					},
				},
			})
		case *Unknown:
			ret = append(ret, &pb.WalletTransaction_IO{
				IoType: &pb.WalletTransaction_IO_Unknown_{
					Unknown: &pb.WalletTransaction_IO_Unknown{},
				},
			})
		}
	}
	return ret
}

func pbIOtoIO(ios []*pb.WalletTransaction_IO, params *params.NetworkParams) ([]IO, error) {
	ret := make([]IO, 0, len(ios))
	for _, io := range ios {
		if io.GetTxIo() != nil {
			addr, err := DecodeAddress(io.GetTxIo().Address, params)
			if err != nil {
				return nil, err
			}
			ret = append(ret, &TxIO{
				Address: addr,
				Amount:  types.Amount(io.GetTxIo().Amount),
			})
		}
		if io.GetUnknown() != nil {
			ret = append(ret, &Unknown{})
		}
	}
	return ret, nil
}
