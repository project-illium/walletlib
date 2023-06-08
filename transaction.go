// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"context"
	"errors"
	"github.com/ipfs/go-datastore/query"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/ilxd/zk/circuits/standard"
	"github.com/project-illium/walletlib/pb"
	"google.golang.org/protobuf/proto"
)

var ErrInsufficientFunds = errors.New("insufficient funds")

func (w *Wallet) buildAndProveTransaction(toAddr Address, amount types.Amount, feePerKB types.Amount) (*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	// Create the input source
	var notes []*pb.SpendNote
	inputSource := func(amount types.Amount) (types.Amount, []*pb.SpendNote, error) {
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
	rawTx, err := BuildTransaction(toAddr, amount, inputSource, w.keychain.Address, w.fetchProofsFunc, feePerKB)
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
	privateParams := standard.PrivateParams{
		Inputs:  rawTx.PrivateInputs,
		Outputs: rawTx.PrivateOutputs,
	}
	sighash, err := rawTx.Tx.SigHash()
	if err != nil {
		return nil, err
	}
	publicParams := standard.PublicParams{
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
