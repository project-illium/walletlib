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

func (w *Wallet) buildAndProveTransaction(toAddr Address, toState [128]byte, amount types.Amount, feePerKB types.Amount, inputCommitments ...types.ID) (*transactions.Transaction, error) {
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

			if time.Unix(note.LockedUntil, 0).After(time.Now()) {
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
	rawTx, err := BuildTransaction([]*RawOutput{{toAddr, amount, toState}}, inputSource, w.keychain.Address, w.GetInclusionProofs, feePerKB)
	if err != nil {
		return nil, err
	}

	outCommitment := rawTx.Tx.Outputs()[0].Commitment
	w.outputMetadata[types.NewID(outCommitment)] = &TxIO{
		Address: toAddr,
		Amount:  amount,
	}

	// Randomize input and output order
	shuffleTransaction(rawTx)

	// Sign the inputs
	sigHash, err := rawTx.Tx.GetStandardTransaction().SigHash()
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

	publicParams := &standard.PublicParams{
		TXORoot:    rawTx.Tx.GetStandardTransaction().TxoRoot,
		SigHash:    sigHash,
		Nullifiers: rawTx.Tx.GetStandardTransaction().Nullifiers,
		Fee:        rawTx.Tx.GetStandardTransaction().Fee,
	}

	for _, out := range rawTx.Tx.GetStandardTransaction().Outputs {
		publicParams.Outputs = append(publicParams.Outputs, standard.PublicOutput{
			Commitment: out.Commitment,
			CipherText: out.Ciphertext,
		})
	}

	proof, err := zk.CreateSnark(standard.StandardCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}

	rawTx.Tx.GetStandardTransaction().Proof = proof

	return rawTx.Tx, nil
}

func (w *Wallet) sweepAndProveTransaction(toAddr Address, feePerKB types.Amount) (*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	results, err := w.ds.Query(context.Background(), query.Query{
		Prefix: NotesDatastoreKeyPrefix,
	})
	if err != nil {
		return nil, err
	}
	notes := make([]*pb.SpendNote, 0, 1)
	for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
		var note pb.SpendNote
		if err := proto.Unmarshal(result.Value, &note); err != nil {
			return nil, err
		}
		if time.Unix(note.LockedUntil, 0).After(time.Now()) {
			continue
		}
		if note.WatchOnly {
			continue
		}
		notes = append(notes, &note)
	}

	// Build tx
	rawTx, err := BuildSweepTransaction(toAddr, notes, w.GetInclusionProofs, feePerKB)
	if err != nil {
		return nil, err
	}

	// Sign the inputs
	sigHash, err := rawTx.Tx.GetStandardTransaction().SigHash()
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

	publicParams := &standard.PublicParams{
		TXORoot:    rawTx.Tx.GetStandardTransaction().TxoRoot,
		SigHash:    sigHash,
		Nullifiers: rawTx.Tx.GetStandardTransaction().Nullifiers,
		Fee:        rawTx.Tx.GetStandardTransaction().Fee,
	}

	for _, out := range rawTx.Tx.GetStandardTransaction().Outputs {
		publicParams.Outputs = append(publicParams.Outputs, standard.PublicOutput{
			Commitment: out.Commitment,
			CipherText: out.Ciphertext,
		})
	}

	proof, err := zk.CreateSnark(standard.StandardCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}

	rawTx.Tx.GetStandardTransaction().Proof = proof

	return rawTx.Tx, nil
}

func (w *Wallet) CreateRawTransaction(inputs []*RawInput, outputs []*RawOutput, addChangeOutput bool, feePerKB types.Amount) (*RawTransaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	var inputSource InputSource
	if len(inputs) == 0 {
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

				if time.Unix(note.LockedUntil, 0).After(time.Now()) {
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
					commitment := sn.Commitment()

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

					notes = append(notes, note)
					total += types.Amount(note.Amount)
					if total > amount {
						return total, notes, nil
					}
				} else {
					return total, notes, errors.New("commitment or private input not set")
				}
			}
			return total, notes, nil
		}
	}

	var changeSource ChangeSource
	if addChangeOutput {
		changeSource = w.Address
	}

	rawTx, err := BuildTransaction(outputs, inputSource, changeSource, w.GetInclusionProofs, feePerKB)
	if err != nil {
		return nil, err
	}

	for i, o := range rawTx.Tx.Outputs() {
		if i < len(outputs) {
			w.outputMetadata[types.NewID(o.Commitment)] = &TxIO{
				Address: outputs[i].Addr,
				Amount:  outputs[i].Amount,
			}
		}
	}

	// Randomize input and output order
	shuffleTransaction(rawTx)
	return rawTx, nil
}

func (w *Wallet) CreateRawStakeTransaction(in *RawInput) (*RawTransaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	if in == nil {
		return nil, errors.New("input is nil")
	}

	var inputNote *pb.SpendNote
	if in.Commitment != nil {
		result, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+hex.EncodeToString(in.Commitment)))
		if err != nil {
			return nil, err
		}

		var note pb.SpendNote
		if err := proto.Unmarshal(result, &note); err != nil {
			return nil, err
		}

		inputNote = &note
	} else if in.PrivateInput != nil {
		us := types.UnlockingScript{
			ScriptCommitment: in.PrivateInput.ScriptCommitment,
			ScriptParams:     in.PrivateInput.ScriptParams,
		}
		scriptHash := us.Hash()

		if len(in.PrivateInput.ScriptParams) < 1 {
			return nil, errors.New("public key not found in private script params")
		}

		sn := &types.SpendNote{
			ScriptHash: scriptHash[:],
			Amount:     types.Amount(in.PrivateInput.Amount),
			AssetID:    in.PrivateInput.AssetID,
			State:      in.PrivateInput.State,
			Salt:       in.PrivateInput.Salt,
		}
		commitment := sn.Commitment()

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

		inputNote = note
	} else {
		return nil, errors.New("commitment or private input must be set")
	}

	networkKey, err := w.keychain.NetworkKey()
	if err != nil {
		return nil, err
	}
	valID, err := peer.IDFromPrivateKey(networkKey)
	if err != nil {
		return nil, err
	}
	valBytes, err := valID.Marshal()
	if err != nil {
		return nil, err
	}

	proofs, root, err := w.GetInclusionProofs(types.NewID(inputNote.Commitment))
	if err != nil {
		return nil, err
	}

	var salt [32]byte
	copy(salt[:], inputNote.Salt)
	nullifier := types.CalculateNullifier(proofs[0].Index, salt, inputNote.UnlockingScript.ScriptCommitment, inputNote.UnlockingScript.ScriptParams...)

	privkey, err := w.keychain.spendKey(inputNote.KeyIndex)
	if err != nil {
		return nil, err
	}

	stakeTx := &transactions.StakeTransaction{
		Validator_ID: valBytes,
		Amount:       inputNote.Amount,
		Nullifier:    nullifier[:],
		TxoRoot:      root[:],
	}

	sigHash, err := stakeTx.SigHash()
	if err != nil {
		return nil, err
	}
	spendSig, err := privkey.Sign(sigHash)
	if err != nil {
		return nil, err
	}

	netSig, err := networkKey.Sign(sigHash)
	if err != nil {
		return nil, err
	}

	stakeTx.Signature = netSig

	privateInput := standard.PrivateInput{
		Amount:          inputNote.Amount,
		CommitmentIndex: proofs[0].Index,
		InclusionProof: standard.InclusionProof{
			Hashes:      proofs[0].Hashes,
			Flags:       proofs[0].Flags,
			Accumulator: proofs[0].Accumulator,
		},
		ScriptCommitment: inputNote.UnlockingScript.ScriptCommitment,
		ScriptParams:     inputNote.UnlockingScript.ScriptParams,
		UnlockingParams:  [][]byte{spendSig},
	}
	copy(privateInput.Salt[:], inputNote.Salt)
	copy(privateInput.AssetID[:], inputNote.Asset_ID)
	copy(privateInput.State[:], inputNote.State)

	rawTx := &RawTransaction{
		Tx: transactions.WrapTransaction(stakeTx),
		PrivateInputs: []standard.PrivateInput{
			privateInput,
		},
	}
	return rawTx, nil
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
		LockedUntil:  note.LockedUntil,
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
		TXORoot:     txoRoot[:],
		SigHash:     sigHash,
		Amount:      note.Amount,
		Nullifier:   nullifier[:],
		LockedUntil: time.Unix(note.LockedUntil, 0),
	}

	proof, err := zk.CreateSnark(stake.StakeCircuit, privateParams, publicParams)
	if err != nil {
		return nil, err
	}
	tx.Proof = proof
	return transactions.WrapTransaction(tx), nil
}

func (w *Wallet) BuildCoinbaseTransaction(unclaimedCoins types.Amount, addr Address, networkKey crypto.PrivKey) (*transactions.Transaction, error) {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

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

	output, privOut, err := buildOutput(addr, unclaimedCoins, [128]byte{})
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
