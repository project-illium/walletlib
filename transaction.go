// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	icrypto "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/ilxd/zk/circparams"
	"github.com/project-illium/walletlib/pb"
	"google.golang.org/protobuf/proto"
	"time"
)

var ErrInsufficientFunds = errors.New("insufficient funds")

func (w *Wallet) buildAndProveTransaction(toAddr Address, toState types.State, amount types.Amount, feePerKB types.Amount, inputCommitments ...types.ID) (*transactions.Transaction, func(), error) {
	w.mtx.RLock()
	w.spendMtx.Lock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	isExchangeAddr := false
	if _, ok := toAddr.(*ExchangeAddress); ok {
		isExchangeAddr = true
	}

	rawTx, publicParams, deleteFunc, err := func() (*RawTransaction, zk.Parameters, func(), error) {
		defer w.mtx.RUnlock()
		defer w.spendMtx.Unlock()

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

					if _, ok := w.inflightUtxos[types.NewID(note.Commitment)]; ok {
						continue
					}

					// Exchange address can only select public utxos
					if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
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
					w.mtx.RUnlock()
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

				if _, ok := w.inflightUtxos[types.NewID(note.Commitment)]; ok {
					continue
				}

				// Exchange address can only select public utxos
				if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
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
			return nil, nil, nil, err
		}

		outCommitment := rawTx.Tx.Outputs()[0].Commitment
		w.metadataMtx.Lock()
		w.outputMetadata[types.NewID(outCommitment)] = &TxIO{
			Address: toAddr,
			Amount:  amount,
		}
		w.metadataMtx.Unlock()

		// Randomize input and output order
		shuffleTransaction(rawTx)

		// Sign the inputs
		sigHash, err := rawTx.Tx.GetStandardTransaction().SigHash()
		if err != nil {
			return nil, nil, nil, err
		}
	inputLoop:
		for i, privIn := range rawTx.PrivateInputs {
			for _, n := range notes {
				if n.AccIndex == privIn.CommitmentIndex {
					privkey, err := w.keychain.spendKey(n.KeyIndex)
					if err != nil {
						return nil, nil, nil, err
					}
					sig, err := privkey.Sign(sigHash)
					if err != nil {
						return nil, nil, nil, err
					}
					if bytes.Equal(n.LockingScript.ScriptCommitment, zk.TimelockedMultisigScriptCommitment()) {
						unlockingParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{sig}, sigHash)
						if err != nil {
							return nil, nil, nil, err
						}
						rawTx.PrivateInputs[i].UnlockingParams = unlockingParams
					} else if bytes.Equal(n.LockingScript.ScriptCommitment, zk.PublicAddressScriptCommitment()) {
						multisigParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{sig}, sigHash)
						if err != nil {
							return nil, nil, nil, err
						}
						pubkey, ok := privkey.GetPublic().(*icrypto.NovaPublicKey)
						if !ok {
							return nil, nil, nil, errors.New("signing error: private key is not type nova")
						}
						pubX, pubY := pubkey.ToXY()
						lockingParams := makePublicAddressLockingParams(pubX, pubY)
						unlockingParams := fmt.Sprintf("(cons %s %s ", lockingParams, multisigParams) + ")"
						rawTx.PrivateInputs[i].UnlockingParams = unlockingParams
					} else {
						rawTx.PrivateInputs[i].UnlockingParams = signatureScript(sig)
					}
					continue inputLoop
				}
			}
		}
		publicParams, err := rawTx.Tx.GetStandardTransaction().ToCircuitParams()
		if err != nil {
			return nil, nil, nil, err
		}
		toDelete := make([]types.ID, 0, len(rawTx.PrivateInputs))
	commitmentLoadLoop:
		for _, privIn := range rawTx.PrivateInputs {
			for _, n := range notes {
				if n.AccIndex == privIn.CommitmentIndex {
					w.inflightUtxos[types.NewID(n.Commitment)] = struct{}{}
					toDelete = append(toDelete, types.NewID(n.Commitment))
					continue commitmentLoadLoop
				}
			}
		}
		deleteFunc := func() {
			w.spendMtx.Lock()
			defer w.spendMtx.Unlock()
			for _, id := range toDelete {
				delete(w.inflightUtxos, id)
			}
		}
		return rawTx, publicParams, deleteFunc, nil
	}()
	if err != nil {
		return nil, nil, err
	}

	// Create the transaction zk proof
	privateParams := &circparams.StandardPrivateParams{
		Inputs:  rawTx.PrivateInputs,
		Outputs: rawTx.PrivateOutputs,
	}

	proof, err := w.prover.Prove(zk.StandardValidationProgram(), privateParams, publicParams)
	if err != nil {
		deleteFunc()
		return nil, nil, err
	}

	rawTx.Tx.GetStandardTransaction().Proof = proof

	return rawTx.Tx, deleteFunc, nil
}

func (w *Wallet) sweepAndProveTransaction(toAddr Address, feePerKB types.Amount, inputCommitments ...types.ID) (*transactions.Transaction, func(), error) {
	w.mtx.RLock()
	w.spendMtx.Lock()
	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	isExchangeAddr := false
	if _, ok := toAddr.(*ExchangeAddress); ok {
		isExchangeAddr = true
	}

	rawTx, publicParams, deleteFunc, err := func() (*RawTransaction, zk.Parameters, func(), error) {
		defer w.mtx.RUnlock()
		defer w.spendMtx.Unlock()

		notes := make([]*pb.SpendNote, 0, 1)
		if len(inputCommitments) > 0 {
			for _, commitment := range inputCommitments {
				result, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
				if err != nil {
					return nil, nil, nil, err
				}

				var note pb.SpendNote
				if err := proto.Unmarshal(result, &note); err != nil {
					return nil, nil, nil, err
				}

				if _, ok := w.inflightUtxos[types.NewID(note.Commitment)]; ok {
					continue
				}

				if time.Unix(note.LockedUntil, 0).After(time.Now()) {
					return nil, nil, nil, errors.New("input commitment is timelocked")
				}

				// Exchange address can only select public utxos
				if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
					continue
				}

				notes = append(notes, &note)
			}
		} else {
			results, err := w.ds.Query(context.Background(), query.Query{
				Prefix: NotesDatastoreKeyPrefix,
			})
			if err != nil {
				return nil, nil, nil, err
			}
			for result, ok := results.NextSync(); ok; result, ok = results.NextSync() {
				var note pb.SpendNote
				if err := proto.Unmarshal(result.Value, &note); err != nil {
					return nil, nil, nil, err
				}
				if time.Unix(note.LockedUntil, 0).After(time.Now()) {
					continue
				}
				if note.WatchOnly {
					continue
				}
				if _, ok := w.inflightUtxos[types.NewID(note.Commitment)]; ok {
					continue
				}
				if time.Unix(note.LockedUntil, 0).After(time.Now()) {
					continue
				}

				if note.Staked {
					continue
				}

				// Exchange address can only select public utxos
				if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
					continue
				}

				notes = append(notes, &note)
			}
		}

		if len(notes) == 0 {
			return nil, nil, nil, errors.New("no spendable utxos in wallet")
		}

		// Build tx
		rawTx, err := BuildSweepTransaction(toAddr, notes, w.GetInclusionProofs, feePerKB)
		if err != nil {
			return nil, nil, nil, err
		}

		outCommitment := rawTx.Tx.Outputs()[0].Commitment
		w.metadataMtx.Lock()
		w.outputMetadata[types.NewID(outCommitment)] = &TxIO{
			Address: toAddr,
			Amount:  rawTx.PrivateOutputs[0].Amount,
		}
		w.metadataMtx.Unlock()

		// Randomize input and output order
		shuffleTransaction(rawTx)

		// Sign the inputs
		sigHash, err := rawTx.Tx.GetStandardTransaction().SigHash()
		if err != nil {
			return nil, nil, nil, err
		}
	inputLoop:
		for i, privIn := range rawTx.PrivateInputs {
			for _, n := range notes {
				if n.AccIndex == privIn.CommitmentIndex {
					privkey, err := w.keychain.spendKey(n.KeyIndex)
					if err != nil {
						return nil, nil, nil, err
					}
					sig, err := privkey.Sign(sigHash)
					if err != nil {
						return nil, nil, nil, err
					}
					if bytes.Equal(n.LockingScript.ScriptCommitment, zk.TimelockedMultisigScriptCommitment()) {
						unlockingParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{sig}, sigHash)
						if err != nil {
							return nil, nil, nil, err
						}
						rawTx.PrivateInputs[i].UnlockingParams = unlockingParams
					} else if bytes.Equal(n.LockingScript.ScriptCommitment, zk.PublicAddressScriptCommitment()) {
						multisigParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{sig}, sigHash)
						if err != nil {
							return nil, nil, nil, err
						}
						pubkey, ok := privkey.GetPublic().(*icrypto.NovaPublicKey)
						if !ok {
							return nil, nil, nil, errors.New("signing error: private key is not type nova")
						}
						pubX, pubY := pubkey.ToXY()
						lockingParams := makePublicAddressLockingParams(pubX, pubY)
						unlockingParams := fmt.Sprintf("(cons %s %s ", lockingParams, multisigParams) + ")"
						rawTx.PrivateInputs[i].UnlockingParams = unlockingParams
					} else {
						rawTx.PrivateInputs[i].UnlockingParams = signatureScript(sig)
					}
					continue inputLoop
				}
			}
		}
		publicParams, err := rawTx.Tx.GetStandardTransaction().ToCircuitParams()
		if err != nil {
			return nil, nil, nil, err
		}
		toDelete := make([]types.ID, 0, len(rawTx.PrivateInputs))
	commitmentLoadLoop:
		for _, privIn := range rawTx.PrivateInputs {
			for _, n := range notes {
				if n.AccIndex == privIn.CommitmentIndex {
					w.inflightUtxos[types.NewID(n.Commitment)] = struct{}{}
					toDelete = append(toDelete, types.NewID(n.Commitment))
					continue commitmentLoadLoop
				}
			}
		}
		deleteFunc := func() {
			w.spendMtx.Lock()
			defer w.spendMtx.Unlock()
			for _, id := range toDelete {
				delete(w.inflightUtxos, id)
			}
		}
		return rawTx, publicParams, deleteFunc, nil
	}()
	if err != nil {
		return nil, nil, err
	}

	// Create the transaction zk proof
	privateParams := &circparams.StandardPrivateParams{
		Inputs:  rawTx.PrivateInputs,
		Outputs: rawTx.PrivateOutputs,
	}

	proof, err := w.prover.Prove(zk.StandardValidationProgram(), privateParams, publicParams)
	if err != nil {
		deleteFunc()
		return nil, nil, err
	}

	rawTx.Tx.GetStandardTransaction().Proof = proof

	return rawTx.Tx, deleteFunc, nil
}

func (w *Wallet) CreateRawTransaction(inputs []*RawInput, outputs []*RawOutput, addChangeOutput bool, feePerKB types.Amount) (*RawTransaction, error) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if feePerKB == 0 {
		feePerKB = w.feePerKB
	}

	isExchangeAddr := false
	for _, output := range outputs {
		if _, ok := output.Addr.(*ExchangeAddress); ok {
			isExchangeAddr = true
			break
		}
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

				// Exchange address can only select public utxos
				if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
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

					// Exchange address can only select public utxos
					if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
						continue
					}

					notes = append(notes, &note)
					total += types.Amount(note.Amount)
					if total > amount {
						return total, notes, nil
					}
				} else if in.PrivateInput != nil {
					scriptCommitment, err := zk.LurkCommit(in.PrivateInput.Script)
					if err != nil {
						return 0, nil, err
					}
					ls := types.LockingScript{
						ScriptCommitment: types.NewID(scriptCommitment),
						LockingParams:    in.PrivateInput.LockingParams,
					}
					scriptHash, err := ls.Hash()
					if err != nil {
						return 0, nil, err
					}

					if len(in.PrivateInput.LockingParams) < 2 {
						return 0, nil, errors.New("public key not found in private script params")
					}

					sn := &types.SpendNote{
						ScriptHash: scriptHash,
						Amount:     in.PrivateInput.Amount,
						AssetID:    in.PrivateInput.AssetID,
						State:      in.PrivateInput.State,
						Salt:       in.PrivateInput.Salt,
					}
					commitment, err := sn.Commitment()
					if err != nil {
						return 0, nil, err
					}

					serializedState, err := in.PrivateInput.State.Serialize(false)
					if err != nil {
						return 0, nil, err
					}

					note := &pb.SpendNote{
						Commitment: commitment[:],
						ScriptHash: scriptHash[:],
						Amount:     uint64(in.PrivateInput.Amount),
						Asset_ID:   in.PrivateInput.AssetID[:],
						State:      serializedState,
						Salt:       in.PrivateInput.Salt[:],
						LockingScript: &pb.LockingScript{
							ScriptCommitment: ls.ScriptCommitment.Bytes(),
							LockingParams:    ls.LockingParams,
						},
						AccIndex: in.PrivateInput.CommitmentIndex,
					}

					// Exchange address can only select public utxos
					if isExchangeAddr && !bytes.Equal(note.ScriptHash, publicAddrScriptHash) {
						continue
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

	for i, in := range rawTx.PrivateInputs {
		if in.Script == "" && inputs[i].PrivateInput != nil {
			rawTx.PrivateInputs[i].Script = inputs[i].PrivateInput.Script
		}
	}

	for i, o := range rawTx.Tx.Outputs() {
		if i < len(outputs) {
			w.metadataMtx.Lock()
			w.outputMetadata[types.NewID(o.Commitment)] = &TxIO{
				Address: outputs[i].Addr,
				Amount:  outputs[i].Amount,
			}
			w.metadataMtx.Unlock()
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
		scriptCommitment, err := zk.LurkCommit(in.PrivateInput.Script)
		if err != nil {
			return nil, err
		}
		ls := types.LockingScript{
			ScriptCommitment: types.NewID(scriptCommitment),
			LockingParams:    in.PrivateInput.LockingParams,
		}
		scriptHash, err := ls.Hash()
		if err != nil {
			return nil, err
		}

		if len(in.PrivateInput.LockingParams) < 2 {
			return nil, errors.New("public key not found in private script params")
		}

		sn := &types.SpendNote{
			ScriptHash: scriptHash,
			Amount:     in.PrivateInput.Amount,
			AssetID:    in.PrivateInput.AssetID,
			State:      in.PrivateInput.State,
			Salt:       in.PrivateInput.Salt,
		}
		commitment, err := sn.Commitment()
		if err != nil {
			return nil, err
		}

		serializedState, err := in.PrivateInput.State.Serialize(false)
		if err != nil {
			return nil, err
		}

		note := &pb.SpendNote{
			Commitment: commitment[:],
			ScriptHash: scriptHash[:],
			Amount:     uint64(in.PrivateInput.Amount),
			Asset_ID:   in.PrivateInput.AssetID[:],
			State:      serializedState,
			Salt:       in.PrivateInput.Salt[:],
			LockingScript: &pb.LockingScript{
				ScriptCommitment: ls.ScriptCommitment.Bytes(),
				LockingParams:    ls.LockingParams,
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
	nullifier, err := types.CalculateNullifier(proofs[0].Index, salt, inputNote.LockingScript.ScriptCommitment, inputNote.LockingScript.LockingParams...)
	if err != nil {
		return nil, err
	}

	privkey, err := w.keychain.spendKey(inputNote.KeyIndex)
	if err != nil {
		return nil, err
	}

	stakeTx := &transactions.StakeTransaction{
		Validator_ID: valBytes,
		Amount:       inputNote.Amount,
		Nullifier:    nullifier[:],
		TxoRoot:      root[:],
		LockedUntil:  inputNote.LockedUntil,
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

	privateInput := circparams.StakePrivateParams{
		Amount:          types.Amount(inputNote.Amount),
		AssetID:         types.NewID(inputNote.Asset_ID),
		Salt:            types.NewID(inputNote.Salt),
		CommitmentIndex: proofs[0].Index,
		InclusionProof: circparams.InclusionProof{
			Hashes: proofs[0].Hashes,
			Flags:  proofs[0].Flags,
		},
		Script:          selectScript(inputNote.LockingScript.ScriptCommitment),
		LockingParams:   inputNote.LockingScript.LockingParams,
		UnlockingParams: signatureScript(spendSig),
	}

	if privateInput.Script == "" && in.PrivateInput != nil {
		privateInput.Script = in.PrivateInput.Script
	}

	state := new(types.State)
	if err := state.Deserialize(inputNote.State); err != nil {
		return nil, err
	}
	privateInput.State = *state

	rawTx := &RawTransaction{
		Tx: transactions.WrapTransaction(stakeTx),
		PrivateInputs: []circparams.PrivateInput{
			circparams.PrivateInput(privateInput),
		},
	}
	return rawTx, nil
}

func (w *Wallet) buildAndProveStakeTransaction(commitment types.ID) (*transactions.Transaction, func(), error) {
	w.mtx.RLock()
	w.spendMtx.Lock()

	tx, privateParams, publicParams, deleteFunc, err := func() (*transactions.StakeTransaction, zk.Parameters, zk.Parameters, func(), error) {
		defer w.mtx.RUnlock()
		defer w.spendMtx.Unlock()

		if _, ok := w.inflightUtxos[commitment]; ok {
			return nil, nil, nil, nil, errors.New("staked utxo is currently locked by another prove function")
		}

		noteBytes, err := w.ds.Get(context.Background(), datastore.NewKey(NotesDatastoreKeyPrefix+commitment.String()))
		if err != nil {
			return nil, nil, nil, nil, err
		}
		var note pb.SpendNote
		if err := proto.Unmarshal(noteBytes, &note); err != nil {
			return nil, nil, nil, nil, err
		}

		networkKey, err := w.keychain.NetworkKey()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		peerID, err := peer.IDFromPrivateKey(networkKey)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		peerIDBytes, err := peerID.Marshal()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		proofs, txoRoot, err := w.GetInclusionProofs(commitment)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if len(proofs) == 0 {
			return nil, nil, nil, nil, errors.New("error fetch inclusion proof")
		}

		nullifier, privateInput, err := buildInput(&note, proofs[0])
		if err != nil {
			return nil, nil, nil, nil, err
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
			return nil, nil, nil, nil, err
		}

		sig, err := networkKey.Sign(sigHash)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tx.Signature = sig

		privkey, err := w.keychain.spendKey(note.KeyIndex)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		txSig, err := privkey.Sign(sigHash)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if bytes.Equal(note.LockingScript.ScriptCommitment, zk.TimelockedMultisigScriptCommitment()) {
			unlockingParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{txSig}, sigHash)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			privateInput.UnlockingParams = unlockingParams
		} else if bytes.Equal(note.LockingScript.ScriptCommitment, zk.PublicAddressScriptCommitment()) {
			multisigParams, err := zk.MakeMultisigUnlockingParams([]crypto.PubKey{privkey.GetPublic()}, [][]byte{txSig}, sigHash)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			pubkey, ok := privkey.GetPublic().(*icrypto.NovaPublicKey)
			if !ok {
				return nil, nil, nil, nil, errors.New("signing error: private key is not type nova")
			}
			pubX, pubY := pubkey.ToXY()
			lockingParams := makePublicAddressLockingParams(pubX, pubY)
			unlockingParams := fmt.Sprintf("(cons %s %s ", lockingParams, multisigParams) + ")"
			privateInput.UnlockingParams = unlockingParams
		} else {
			privateInput.UnlockingParams = signatureScript(txSig)
		}

		privateParams := &circparams.StakePrivateParams{
			Amount:          privateInput.Amount,
			AssetID:         privateInput.AssetID,
			Salt:            privateInput.Salt,
			State:           privateInput.State,
			CommitmentIndex: privateInput.CommitmentIndex,
			InclusionProof:  privateInput.InclusionProof,
			Script:          privateInput.Script,
			LockingParams:   privateInput.LockingParams,
			UnlockingParams: privateInput.UnlockingParams,
		}

		publicParams, err := tx.ToCircuitParams()
		if err != nil {
			return nil, nil, nil, nil, err
		}

		w.inflightUtxos[commitment] = struct{}{}
		deleteFunc := func() {
			w.spendMtx.Lock()
			defer w.spendMtx.Unlock()
			delete(w.inflightUtxos, commitment)
		}
		return tx, privateParams, publicParams, deleteFunc, nil
	}()
	if err != nil {
		return nil, nil, err
	}

	proof, err := w.prover.Prove(zk.StakeValidationProgram(), privateParams, publicParams)
	if err != nil {
		deleteFunc()
		return nil, nil, err
	}
	tx.Proof = proof
	return transactions.WrapTransaction(tx), deleteFunc, nil
}

func (w *Wallet) BuildCoinbaseTransaction(unclaimedCoins types.Amount, addr Address, networkKey crypto.PrivKey) (*transactions.Transaction, error) {
	w.mtx.RLock()

	tx, privateParams, publicParams, err := func() (*transactions.CoinbaseTransaction, zk.Parameters, zk.Parameters, error) {
		defer w.mtx.RUnlock()

		var err error
		if addr == nil {
			addr, err = w.keychain.Address()
			if err != nil {
				return nil, nil, nil, err
			}
		}

		peerID, err := peer.IDFromPrivateKey(networkKey)
		if err != nil {
			return nil, nil, nil, err
		}

		peerIDBytes, err := peerID.Marshal()
		if err != nil {
			return nil, nil, nil, err
		}

		output, privOut, err := buildOutput(addr, unclaimedCoins, types.State{})
		if err != nil {
			return nil, nil, nil, err
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
			return nil, nil, nil, err
		}

		sig, err := networkKey.Sign(sigHash)
		if err != nil {
			return nil, nil, nil, err
		}
		tx.Signature = sig

		// Create the transaction zk proof
		privateParams := circparams.CoinbasePrivateParams(
			[]circparams.PrivateOutput{privOut},
		)

		publicParams, err := tx.ToCircuitParams()
		if err != nil {
			return nil, nil, nil, err
		}
		return tx, &privateParams, publicParams, nil
	}()
	if err != nil {
		return nil, err
	}

	proof, err := w.prover.Prove(zk.CoinbaseValidationProgram(), privateParams, publicParams)
	if err != nil {
		return nil, err
	}
	tx.Proof = proof
	return transactions.WrapTransaction(tx), nil
}

func signatureScript(sig []byte) string {
	sigRx, sigRy, sigS := icrypto.UnmarshalSignature(sig)
	return fmt.Sprintf("(cons 0x%x (cons 0x%x (cons 0x%x nil)))", sigRx, sigRy, sigS)
}
