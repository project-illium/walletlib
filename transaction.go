// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/ilxd/zk/circuits/stake"
	"github.com/project-illium/ilxd/zk/circuits/standard"
	"github.com/project-illium/walletlib/pb"
	"google.golang.org/protobuf/proto"
	"time"
)

var ErrInsufficientFunds = errors.New("insufficient funds")

func (w *Wallet) buildAndProveTransaction(toAddr Address, amount types.Amount, feePerKB types.Amount, inputCommitments ...types.ID) (*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	// Create the input source
	var notes []*pb.SpendNote
	inputSource := func(amount types.Amount) (types.Amount, []*pb.SpendNote, error) {
		if len(inputCommitments) > 0 {
			total := types.Amount(0)
			for _, commitment := range inputCommitments {
				result, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
				if err != nil {
					return 0, nil, err
				}

				var note pb.SpendNote
				if err := proto.Unmarshal(result, &note); err != nil {
					return 0, nil, err
				}

				if IsDustInput(types.Amount(note.Amount), feePerKB) {
					continue
				}
				notes = append(notes, &note)
				total += types.Amount(note.Amount)
				if total > amount {
					return total, notes, nil
				}
			}
			return total, notes, nil
		}
		results, err := w.ds.Query(context.Background(), query.Query{
			Prefix: NotesDatastoreKeyPrefix,
		})
		if err != nil {
			return 0, nil, err
		}
		notes = make([]*pb.SpendNote, 0, 1)
		total := types.Amount(0)
		for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
			var note pb.SpendNote
			if err := proto.Unmarshal(result.Value, &note); err != nil {
				return 0, nil, err
			}

			if note.WatchOnly {
				continue
			}

			if note.Staked {
				continue
			}

			if IsDustInput(types.Amount(note.Amount), feePerKB) {
				continue
			}

			notes = append(notes, &note)
			total += types.Amount(note.Amount)
			if total > amount {
				return total, notes, nil
			}
		}
		return total, notes, nil
	}

	// Build tx
	rawTx, err := BuildTransaction([]*RawOutput{{toAddr, amount}}, inputSource, w.keychain.Address, w.GetInclusionProofs, feePerKB)
	if err != nil {
		return nil, err
	}

	// Sign the inputs
	sigHash, err := rawTx.Tx.SigHash()
	if err != nil {
		return nil, err
	}
inputLoop:
	for i, privIn := range rawTx.PrivateInputs {
		for _, n := range notes {
			if n.AccIndex == privIn.CommitmentIndex {
				privkey, err := w.keychain.spendKey(n.KeyIndex)
				if err != nil {
					return nil, err
				}
				sig, err := privkey.Sign(sigHash)
				if err != nil {
					return nil, err
				}
				rawTx.PrivateInputs[i].UnlockingParams = [][]byte{sig}
				continue inputLoop
			}
		}
	}

	// Create the transaction zk proof
	privateParams := &standard.PrivateParams{
		Inputs:  rawTx.PrivateInputs,
		Outputs: rawTx.PrivateOutputs,
	}
	sighash, err := rawTx.Tx.SigHash()
	if err != nil {
		return nil, err
	}
	publicParams := &standard.PublicParams{
		TXORoot:    rawTx.Tx.TxoRoot,
		SigHash:    sighash,
		Nullifiers: rawTx.Tx.Nullifiers,
		Fee:        rawTx.Tx.Fee,
	}

	for _, out := range rawTx.Tx.Outputs {
		publicParams.Outputs = append(publicParams.Outputs, standard.PublicOutput{
			Commitment: out.Commitment,
			CipherText: out.Ciphertext,
		})
	}

	proof, err := zk.CreateSnark(standard.StandardCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}

	rawTx.Tx.Proof = proof

	return transactions.WrapTransaction(rawTx.Tx), nil
}

func (w *Wallet) CreateRawTransaction(inputs []*RawInput, outputs []*RawOutput, addChangeOutput bool, feePerKB types.Amount) (*RawTransaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	var inputSource InputSource
	if inputs == nil || len(inputs) == 0 {
		inputSource = func(amount types.Amount) (types.Amount, []*pb.SpendNote, error) {
			results, err := w.ds.Query(context.Background(), query.Query{
				Prefix: NotesDatastoreKeyPrefix,
			})
			if err != nil {
				return 0, nil, err
			}
			notes := make([]*pb.SpendNote, 0, 1)
			total := types.Amount(0)
			for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
				var note pb.SpendNote
				if err := proto.Unmarshal(result.Value, &note); err != nil {
					return 0, nil, err
				}

				if note.WatchOnly {
					continue
				}

				if note.Staked {
					continue
				}

				if IsDustInput(types.Amount(note.Amount), feePerKB) {
					continue
				}

				notes = append(notes, &note)
				total += types.Amount(note.Amount)
				if total > amount {
					return total, notes, nil
				}
			}
			return total, notes, nil
		}
	} else {
		inputSource = func(amount types.Amount) (types.Amount, []*pb.SpendNote, error) {
			notes := make([]*pb.SpendNote, 0, 1)
			total := types.Amount(0)
			for _, in := range inputs {
				if in.Commitment != nil {
					result, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(in.Commitment)))
					if err != nil {
						return 0, nil, err
					}

					var note pb.SpendNote
					if err := proto.Unmarshal(result, &note); err != nil {
						return 0, nil, err
					}

					if IsDustInput(types.Amount(note.Amount), feePerKB) {
						continue
					}
					notes = append(notes, &note)
					total += types.Amount(note.Amount)
					if total > amount {
						return total, notes, nil
					}
				} else if in.PrivateInput != nil {

					us := types.UnlockingScript{
						ScriptCommitment: in.PrivateInput.ScriptCommitment,
						ScriptParams:     in.PrivateInput.ScriptParams,
					}
					scriptHash := us.Hash()

					if len(in.PrivateInput.ScriptParams) < 1 {
						return 0, nil, errors.New("public key not found in private script params")
					}

					sn := &types.SpendNote{
						ScriptHash: scriptHash[:],
						Amount:     types.Amount(in.PrivateInput.Amount),
						AssetID:    in.PrivateInput.AssetID,
						State:      in.PrivateInput.State,
						Salt:       in.PrivateInput.Salt,
					}
					commitment, err := sn.Commitment()
					if err != nil {
						return 0, nil, err
					}

					note := &pb.SpendNote{
						Commitment: commitment[:],
						ScriptHash: scriptHash[:],
						Amount:     in.PrivateInput.Amount,
						Asset_ID:   in.PrivateInput.AssetID[:],
						State:      in.PrivateInput.State[:],
						Salt:       in.PrivateInput.Salt[:],
						UnlockingScript: &pb.UnlockingScript{
							ScriptCommitment: in.PrivateInput.ScriptCommitment,
							ScriptParams:     in.PrivateInput.ScriptParams,
						},
						AccIndex: in.PrivateInput.CommitmentIndex,
					}
					if IsDustInput(types.Amount(note.Amount), feePerKB) {
						continue
					}
					notes = append(notes, note)
					total += types.Amount(note.Amount)
					if total > amount {
						return total, notes, nil
					}
				} else {
					return total, notes, errors.New("commitment or private key not set")
				}
			}
			return total, notes, nil
		}
	}

	var changeSource ChangeSource
	if addChangeOutput {
		changeSource = w.Address
	}

	return BuildTransaction(outputs, inputSource, changeSource, w.GetInclusionProofs, feePerKB)
}

func ProveRawTransaction(rawTx *RawTransaction, keys []crypto.PrivKey) (*transactions.Transaction, error) {
	if len(keys) != len(rawTx.PrivateInputs) {
		return nil, errors.New("invalid number of keys")
	}

	// Sign the inputs
	sigHash, err := rawTx.Tx.SigHash()
	if err != nil {
		return nil, err
	}

	for i := range rawTx.PrivateInputs {
		sig, err := keys[i].Sign(sigHash)
		if err != nil {
			return nil, err
		}
		rawTx.PrivateInputs[i].UnlockingParams = [][]byte{sig}
	}

	// Create the transaction zk proof
	privateParams := &standard.PrivateParams{
		Inputs:  rawTx.PrivateInputs,
		Outputs: rawTx.PrivateOutputs,
	}
	sighash, err := rawTx.Tx.SigHash()
	if err != nil {
		return nil, err
	}
	publicParams := &standard.PublicParams{
		TXORoot:    rawTx.Tx.TxoRoot,
		SigHash:    sighash,
		Nullifiers: rawTx.Tx.Nullifiers,
		Fee:        rawTx.Tx.Fee,
	}

	for _, out := range rawTx.Tx.Outputs {
		publicParams.Outputs = append(publicParams.Outputs, standard.PublicOutput{
			Commitment: out.Commitment,
			CipherText: out.Ciphertext,
		})
	}

	proof, err := zk.CreateSnark(standard.StandardCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}

	rawTx.Tx.Proof = proof
	return transactions.WrapTransaction(rawTx.Tx), nil
}

func (w *Wallet) buildAndProveStakeTransaction(commitment types.ID) (*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	noteBytes, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
	if err != nil {
		return nil, err
	}
	var note pb.SpendNote
	if err := proto.Unmarshal(noteBytes, &note); err != nil {
		return nil, err
	}

	networkKey, err := w.keychain.NetworkKey()
	if err != nil {
		return nil, err
	}

	peerID, err := peer.IDFromPrivateKey(networkKey)
	if err != nil {
		return nil, err
	}

	peerIDBytes, err := peerID.Marshal()
	if err != nil {
		return nil, err
	}
	var salt [32]byte
	copy(salt[:], note.Salt)

	proofs, txoRoot, err := w.GetInclusionProofs(commitment)
	if err != nil {
		return nil, err
	}
	if len(proofs) == 0 {
		return nil, errors.New("error fetch inclusion proof")
	}

	nullifier, privateInput, err := buildInput(&note, proofs[0])
	if err != nil {
		return nil, err
	}

	tx := &transactions.StakeTransaction{
		Validator_ID: peerIDBytes,
		Amount:       note.Amount,
		Nullifier:    nullifier[:],
		TxoRoot:      txoRoot[:],
		Signature:    nil,
		Proof:        nil,
	}

	sigHash, err := tx.SigHash()
	if err != nil {
		return nil, err
	}

	sig, err := networkKey.Sign(sigHash)
	if err != nil {
		return nil, err
	}
	tx.Signature = sig

	// Create the transaction zk proof
	privateParams := &stake.PrivateParams{
		AssetID:          privateInput.AssetID,
		Salt:             privateInput.Salt,
		State:            privateInput.State,
		CommitmentIndex:  privateInput.CommitmentIndex,
		InclusionProof:   privateInput.InclusionProof,
		ScriptCommitment: privateInput.ScriptCommitment,
		ScriptParams:     privateInput.ScriptParams,
		UnlockingParams:  privateInput.UnlockingParams,
	}

	publicParams := &stake.PublicParams{
		TXORoot:   txoRoot[:],
		SigHash:   sigHash,
		Amount:    note.Amount,
		Nullifier: nullifier[:],
		Locktime:  time.Time{},
	}

	proof, err := zk.CreateSnark(stake.StakeCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}
	tx.Proof = proof
	return transactions.WrapTransaction(tx), nil
}

func (w *Wallet) BuildCoinbaseTransaction(unclaimedCoins types.Amount, addr Address, networkKey crypto.PrivKey) (*transactions.Transaction, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	var err error
	if addr == nil {
		addr, err = w.keychain.Address()
		if err != nil {
			return nil, err
		}
	}

	peerID, err := peer.IDFromPrivateKey(networkKey)
	if err != nil {
		return nil, err
	}

	peerIDBytes, err := peerID.Marshal()
	if err != nil {
		return nil, err
	}

	output, privOut, err := buildOutput(addr, unclaimedCoins)
	if err != nil {
		return nil, err
	}

	tx := &transactions.CoinbaseTransaction{
		Validator_ID: peerIDBytes,
		NewCoins:     uint64(unclaimedCoins),
		Outputs:      []*transactions.Output{output},
		Signature:    nil,
		Proof:        nil,
	}

	sigHash, err := tx.SigHash()
	if err != nil {
		return nil, err
	}

	sig, err := networkKey.Sign(sigHash)
	if err != nil {
		return nil, err
	}
	tx.Signature = sig

	// Create the transaction zk proof
	privateParams := &standard.PrivateParams{
		Outputs: []standard.PrivateOutput{privOut},
	}

	publicParams := &standard.PublicParams{
		Coinbase: uint64(unclaimedCoins),
	}

	for _, out := range tx.Outputs {
		publicParams.Outputs = append(publicParams.Outputs, standard.PublicOutput{
			Commitment: out.Commitment,
			CipherText: out.Ciphertext,
		})
	}

	proof, err := zk.CreateSnark(standard.StandardCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}
	tx.Proof = proof
	return transactions.WrapTransaction(tx), nil
}
