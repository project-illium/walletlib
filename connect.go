// Copyright (c) 2024 The illium developers
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
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/walletlib/pb"
	"google.golang.org/protobuf/proto"
)

func (w *Wallet) connectBlock(blk *blocks.Block, scanner *TransactionScanner, accdb *blockchain.AccumulatorDB, isRescan bool) {
	matches := scanner.ScanOutputs(blk)
	accumulator := accdb.Accumulator()

	matchedTxs := 0
	for _, tx := range blk.Transactions {
		var (
			isOurs    bool
			walletOut types.Amount
			walletIn  types.Amount
			ins       []IO
			outs      []IO
		)
		for _, n := range tx.Nullifiers() {
			if commitment, ok := w.nullifiers[n]; ok {
				in, err := w.connectInput(n, commitment)
				if err != nil {
					log.WithCaller(true).Error("Error connecting input to wallet", log.ArgsFromMap(map[string]any{
						"block":  blk.ID().String(),
						"height": blk.Header.Height,
						"error":  err,
					}))
					continue
				}

				walletOut += in.Amount
				isOurs = true
				accumulator.DropProof(commitment.Bytes())
				ins = append(ins, in)
				log.Debug("Wallet detected spend of nullifier", log.ArgsFromMap(map[string]any{
					"nullifier": n.String(),
					"height":    blk.Header.Height,
				}))
			} else {
				ins = append(ins, &Unknown{})
			}
		}
		for _, out := range tx.Outputs() {
			match, ok := matches[types.NewID(out.Commitment)]
			if w.chainClient.IsFullClient() {
				accumulator.Insert(out.Commitment, ok)
			}
			if ok {
				txioOut, err := w.connectOutput(match, out.Commitment, accumulator.NumElements()-1)
				if err != nil {
					log.WithCaller(true).Error("Error connecting output to wallet", log.ArgsFromMap(map[string]any{
						"block":  blk.ID().String(),
						"height": blk.Header.Height,
						"error":  err,
					}))
					accumulator.DropProof(out.Commitment)
					continue
				}

				walletIn += txioOut.Amount
				isOurs = true
				outs = append(outs, txioOut)
				w.spendMtx.Lock()
				delete(w.inflightUtxos, types.NewID(out.Commitment))
				w.spendMtx.Unlock()
				log.Debug("Wallet detected incoming output", log.ArgsFromMap(map[string]any{
					"commitment": types.NewID(out.Commitment).String(),
					"txid":       tx.ID().String(),
					"height":     blk.Header.Height,
				}))
			} else {
				w.metadataMtx.Lock()
				txio, ok := w.outputMetadata[types.NewID(out.Commitment)]
				if ok {
					outs = append(outs, txio)
					delete(w.outputMetadata, types.NewID(out.Commitment))
				} else {
					outs = append(outs, &Unknown{})
				}
				w.metadataMtx.Unlock()
			}
		}

		stakeTx := tx.GetStakeTransaction()
		if stakeTx != nil {
			commitment, ok := w.nullifiers[types.NewNullifier(stakeTx.Nullifier)]
			if ok {
				if err := w.connectStake(commitment); err != nil {
					log.WithCaller(true).Error("Error connecting stake tx to wallet", log.ArgsFromMap(map[string]any{
						"block":  blk.ID().String(),
						"height": blk.Header.Height,
						"error":  err,
					}))
				}
				w.spendMtx.Lock()
				delete(w.inflightUtxos, commitment)
				w.spendMtx.Unlock()
				log.Debug("Wallet detected stake tx", log.ArgsFromMap(map[string]any{
					"txid":   tx.ID().String(),
					"height": blk.Header.Height,
				}))
			}
		}

		flushMode := blockchain.FlushPeriodic
		if isOurs {
			flushMode = blockchain.FlushRequired
		}
		if w.chainClient.IsFullClient() {
			if err := accdb.Commit(accumulator, blk.Header.Height, flushMode); err != nil {
				log.WithCaller(true).Error("Error committing accumulator", log.ArgsFromMap(map[string]any{
					"block":  blk.ID().String(),
					"height": blk.Header.Height,
					"error":  err,
				}))
			}
		}
		if !isRescan && blk.Header.Height > 0 {
			w.chainHeight = blk.Header.Height
		}

		if isOurs {
			matchedTxs++
			txid := tx.ID()
			wtx := &pb.WalletTransaction{
				Txid:    txid[:],
				AmtIn:   uint64(walletIn),
				AmtOut:  uint64(walletOut),
				Inputs:  ioToPBio(ins),
				Outputs: ioToPBio(outs),
			}
			if err := w.connectTransaction(wtx, blk.Header.Height, isRescan); err != nil {
				log.WithCaller(true).Error("Error connecting transaction to wallet", log.ArgsFromMap(map[string]any{
					"block":  blk.ID().String(),
					"height": blk.Header.Height,
					"error":  err,
				}))
			}
			direction := "incoming"
			amtStr := fmt.Sprintf("+%d", walletIn-walletOut)
			if walletOut > walletIn {
				direction = "outgoing"
				amtStr = fmt.Sprintf("-%d", walletOut-walletIn)
			}
			log.Info(fmt.Sprintf("New %s wallet transaction", direction), log.ArgsFromMap(map[string]any{
				"txid":   tx.ID().String(),
				"amount": amtStr,
			}))
			w.txSubMtx.RLock()
			for _, sub := range w.txSubs {
				go func(s *TransactionSubscription) {
					s.C <- &WalletTransaction{
						Txid:      tx.ID(),
						AmountIn:  walletIn,
						AmountOut: walletOut,
						Inputs:    ins,
						Outputs:   outs,
					}
				}(sub)
			}
			w.txSubMtx.RUnlock()
		}
	}
	log.WithCaller(true).Trace("Wallet processed block", log.ArgsFromMap(map[string]any{
		"height":  blk.Header.Height,
		"matches": matchedTxs,
	}))
}

func (w *Wallet) connectInput(n types.Nullifier, commitment types.ID) (*TxIO, error) {
	b, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
	if err != nil {
		return nil, err
	}
	var note pb.SpendNote
	if err := proto.Unmarshal(b, &note); err != nil {
		return nil, err
	}
	inAddr, err := DecodeAddress(note.Address, w.params)
	if err != nil {
		return nil, err
	}
	if err := w.ds.Delete(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String())); err != nil {
		return nil, err
	}
	if err := w.ds.Delete(context.Background(), datastore.NewKey(NullifierKeyPrefix+n.String())); err != nil {
		return nil, err
	}
	delete(w.nullifiers, n)
	in := &TxIO{
		Address: inAddr,
		Amount:  types.Amount(note.Amount),
	}
	return in, nil
}

func (w *Wallet) connectOutput(match *ScanMatch, outputCommitment []byte, commitmentIndex uint64) (*TxIO, error) {
	addrInfo, err := w.keychain.addrInfo(match.Key)
	if err != nil {
		return nil, err
	}

	note := types.SpendNote{}
	if err := note.Deserialize(match.DecryptedNote); err != nil {
		return nil, err
	}
	commitment, err := note.Commitment()
	if err != nil {
		return nil, fmt.Errorf("invalid commitment: %s", err)
	}
	if !bytes.Equal(commitment.Bytes(), outputCommitment) {
		return nil, errors.New("decrypted note does not match commitment")
	}
	if note.AssetID.Compare(types.IlliumCoinID) != 0 {
		return nil, errors.New("note assetID not illium coin ID")
	}
	if note.Amount == 0 {
		return nil, errors.New("note amount is zero")
	}

	locktime := int64(0)
	if bytes.Equal(note.ScriptHash.Bytes(), publicAddrScriptHash) {
		lockingParams := makePublicAddressLockingParams(addrInfo.LockingScript.LockingParams[0], addrInfo.LockingScript.LockingParams[1])
		addr, err := NewPublicAddress(lockingParams, w.params)
		if err != nil {
			return nil, fmt.Errorf("error creating timelocked address: %s", err)
		}
		sh := addr.ScriptHash()
		if len(note.State) < 1 || !bytes.Equal(note.State[0], sh[:]) {
			return nil, errors.New("output state doesn't match public address")
		}
		addrInfo.Addr = addr.String()
		addrInfo.ScriptHash = publicAddrScriptHash
		addrInfo.LockingScript.ScriptCommitment = zk.PublicAddressScriptCommitment()
		addrInfo.LockingScript.LockingParams = nil
	} else if len(note.State) > 0 && len(note.State[0]) >= 8 {
		script := types.LockingScript{
			ScriptCommitment: types.NewID(zk.TimelockedMultisigScriptCommitment()),
			LockingParams: [][]byte{
				note.State[0][:8],
				{0x01},
				addrInfo.LockingScript.LockingParams[0],
				addrInfo.LockingScript.LockingParams[1],
			},
		}
		scriptHash, err := script.Hash()
		if err != nil {
			return nil, fmt.Errorf("error computing script hash: %s", err)
		}

		if bytes.Equal(note.ScriptHash.Bytes(), scriptHash[:]) {
			locktime = int64(binary.BigEndian.Uint64(note.State[0][:8]))

			priv, err := lcrypto.UnmarshalPrivateKey(addrInfo.ViewPrivKey)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling view key: %s", err)
			}

			addr, err := NewBasicAddress(script, priv.GetPublic(), w.params)
			if err != nil {
				return nil, fmt.Errorf("error creating timelocked address: %s", err)
			}
			addrInfo.Addr = addr.String()
			addrInfo.ScriptHash = scriptHash[:]
			addrInfo.LockingScript.ScriptCommitment = script.ScriptCommitment.Bytes()
			addrInfo.LockingScript.LockingParams = script.LockingParams
		}
	}

	if !bytes.Equal(note.ScriptHash.Bytes(), addrInfo.ScriptHash) {
		return nil, errors.New("note doesn't match script hash")
	}

	serializedState, err := note.State.Serialize(false)
	if err != nil {
		return nil, fmt.Errorf("error serializing state: %s", err)
	}

	dbNote := &pb.SpendNote{
		Address:    addrInfo.Addr,
		Commitment: outputCommitment,
		KeyIndex:   addrInfo.KeyIndex,
		ScriptHash: note.ScriptHash.Bytes(),
		Amount:     uint64(note.Amount),
		Asset_ID:   note.AssetID[:],
		State:      serializedState,
		Salt:       note.Salt[:],
		AccIndex:   commitmentIndex,
		WatchOnly:  addrInfo.WatchOnly,
		LockingScript: &pb.LockingScript{
			ScriptCommitment: addrInfo.LockingScript.ScriptCommitment,
			LockingParams:    addrInfo.LockingScript.LockingParams,
		},
		LockedUntil: locktime,
	}
	ser, err := proto.Marshal(dbNote)
	if err != nil {
		return nil, fmt.Errorf("error marshalling note: %s", err)
	}
	if _, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(outputCommitment))); err != datastore.ErrNotFound {
		return nil, errors.New("commitment already exists in database")
	}

	if err := w.ds.Put(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(outputCommitment)), ser); err != nil {
		return nil, err
	}
	nullifier, err := types.CalculateNullifier(commitmentIndex, note.Salt, addrInfo.LockingScript.ScriptCommitment, addrInfo.LockingScript.LockingParams...)
	if err != nil {
		return nil, err
	}

	if err := w.ds.Put(context.Background(), datastore.NewKey(NullifierKeyPrefix+nullifier.String()), outputCommitment); err != nil {
		return nil, err
	}

	addr, err := DecodeAddress(addrInfo.Addr, w.params)
	if err != nil {
		return nil, err
	}

	w.nullifiers[nullifier] = types.NewID(outputCommitment)
	out := &TxIO{
		Address: addr,
		Amount:  note.Amount,
	}
	return out, nil
}

func (w *Wallet) connectStake(commitment types.ID) error {
	b, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
	if err != nil {
		return err
	}
	var note pb.SpendNote
	if err := proto.Unmarshal(b, &note); err != nil {
		return err
	}
	note.Staked = true

	ser, err := proto.Marshal(&note)
	if err != nil {
		return err
	}
	if err := w.ds.Put(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()), ser); err != nil {
		return err
	}
	return nil
}

func (w *Wallet) connectTransaction(wtx *pb.WalletTransaction, height uint32, isRescan bool) error {
	ser, err := proto.Marshal(wtx)
	if err != nil {
		return err
	}
	if err := w.ds.Put(context.Background(), datastore.NewKey(TransactionDatastoreKeyPrefix+hex.EncodeToString(wtx.Txid)), ser); err != nil {
		return err
	}

	if !isRescan && height > 0 {
		heightBytes := make([]byte, 32)
		binary.BigEndian.PutUint32(heightBytes, w.chainHeight)
		if err := w.ds.Put(context.Background(), datastore.NewKey(WalletHeightDatastoreKey), heightBytes); err != nil {
			return err
		}
	}
	return nil
}
