// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"errors"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk"
	"github.com/project-illium/ilxd/zk/circparams"
	"github.com/project-illium/walletlib/pb"
	mrand "math/rand"
	"time"
)

const DefaultLocktimePrecision = 60 * 20

type RawTransaction struct {
	Tx             *transactions.Transaction
	PrivateInputs  []circparams.PrivateInput
	PrivateOutputs []circparams.PrivateOutput
}

// RawInput represents either a commitment or a private input
// Set one or the other fields but not both.
type RawInput struct {
	Commitment   []byte
	PrivateInput *circparams.PrivateInput
}
type RawOutput struct {
	Addr   Address
	Amount types.Amount
	State  types.State
}

type InputSource func(amount types.Amount) (types.Amount, []*pb.SpendNote, error)
type ChangeSource func() (Address, error)
type ProofsSource func(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error)

func BuildTransaction(outputs []*RawOutput, fetchInputs InputSource, fetchChange ChangeSource, fetchProofs ProofsSource, feePerKB types.Amount) (*RawTransaction, error) {
	raw := &RawTransaction{
		Tx:             &transactions.Transaction{},
		PrivateInputs:  []circparams.PrivateInput{},
		PrivateOutputs: []circparams.PrivateOutput{},
	}

	standardTx := &transactions.StandardTransaction{
		Locktime: &transactions.Locktime{
			Timestamp: time.Now().Unix(),
			Precision: DefaultLocktimePrecision,
		},
	}

	// First calculate the out amount
	toAmt := types.Amount(0)
	for _, o := range outputs {
		toAmt += o.Amount
	}

	// First select the inputs that will cover the amount
	inputNotes, fee, err := selectInputs(toAmt, fetchInputs, feePerKB)
	if err != nil {
		return nil, err
	}
	standardTx.Fee = uint64(fee)

	// In this iteration extract the commitments and sum the total input amount
	totalIn := types.Amount(0)
	commitments := make([]types.ID, 0, len(inputNotes))
	for _, in := range inputNotes {
		totalIn += types.Amount(in.Amount)
		commitments = append(commitments, types.NewID(in.Commitment))
	}

	// We have to fetch the proofs all at once rather than one at a time
	// because a new block could be committed between queries and the root
	// hashes for the proofs would be different.
	proofs, txoRoot, err := fetchProofs(commitments...)
	if err != nil {
		return nil, err
	}
	standardTx.TxoRoot = txoRoot[:]

	// Build the inputs
	for i, note := range inputNotes {
		nullifier, privIn, err := buildInput(note, proofs[i])
		if err != nil {
			return nil, err
		}
		standardTx.Nullifiers = append(standardTx.Nullifiers, nullifier[:])
		raw.PrivateInputs = append(raw.PrivateInputs, privIn)
	}

	// Build the outputs
	for _, o := range outputs {
		txOut, privOut, err := buildOutput(o.Addr, o.Amount, o.State)
		if err != nil {
			return nil, err
		}
		standardTx.Outputs = append(standardTx.Outputs, txOut)
		raw.PrivateOutputs = append(raw.PrivateOutputs, privOut)
	}

	// If we need a change output build that
	if totalIn > toAmt+fee && fetchChange != nil {
		changeAddr, err := fetchChange()
		if err != nil {
			return nil, err
		}

		txOut, privOut, err := buildOutput(changeAddr, totalIn-(toAmt+fee), types.State{})
		if err != nil {
			return nil, err
		}
		standardTx.Outputs = append(standardTx.Outputs, txOut)
		raw.PrivateOutputs = append(raw.PrivateOutputs, privOut)
	}

	raw.Tx = transactions.WrapTransaction(standardTx)

	// Randomize input and output order
	shuffleTransaction(raw)

	return raw, nil
}

func BuildSweepTransaction(toAddr Address, inputNotes []*pb.SpendNote, fetchProofs ProofsSource, feePerKB types.Amount) (*RawTransaction, error) {
	raw := &RawTransaction{
		Tx:             &transactions.Transaction{},
		PrivateInputs:  []circparams.PrivateInput{},
		PrivateOutputs: []circparams.PrivateOutput{},
	}

	fee := ComputeFee(len(inputNotes), 1, feePerKB)
	standardTx := &transactions.StandardTransaction{
		Fee: uint64(fee),
		Locktime: &transactions.Locktime{
			Timestamp: time.Now().Unix(),
			Precision: DefaultLocktimePrecision,
		},
	}

	totalIn := types.Amount(0)
	commitments := make([]types.ID, 0, len(inputNotes))
	for _, in := range inputNotes {
		totalIn += types.Amount(in.Amount)
		commitments = append(commitments, types.NewID(in.Commitment))
	}

	proofs, txoRoot, err := fetchProofs(commitments...)
	if err != nil {
		return nil, err
	}
	standardTx.TxoRoot = txoRoot[:]

	// Build the inputs
	for i, note := range inputNotes {
		nullifier, privIn, err := buildInput(note, proofs[i])
		if err != nil {
			return nil, err
		}
		standardTx.Nullifiers = append(standardTx.Nullifiers, nullifier[:])
		raw.PrivateInputs = append(raw.PrivateInputs, privIn)
	}

	txOut, privOut, err := buildOutput(toAddr, totalIn-fee, types.State{})
	if err != nil {
		return nil, err
	}
	standardTx.Outputs = append(standardTx.Outputs, txOut)
	raw.PrivateOutputs = append(raw.PrivateOutputs, privOut)

	raw.Tx = transactions.WrapTransaction(standardTx)

	return raw, nil
}

func selectInputs(amount types.Amount, fetchInputs InputSource, feePerKB types.Amount) ([]*pb.SpendNote, types.Amount, error) {
	fee := ComputeFee(0, 2, feePerKB)

	for {
		total, notes, err := fetchInputs(amount + fee)
		if err != nil {
			return nil, 0, err
		}
		if total < amount+fee {
			return nil, 0, ErrInsufficientFunds
		}
		fee = ComputeFee(len(notes), 2, feePerKB)
		remainingAmount := total - amount
		if remainingAmount < fee {
			continue
		}

		return notes, fee, nil
	}
}

func buildInput(note *pb.SpendNote, proof *blockchain.InclusionProof) (types.Nullifier, circparams.PrivateInput, error) {
	privIn := circparams.PrivateInput{
		Amount:          types.Amount(note.Amount),
		AssetID:         types.NewID(note.Asset_ID),
		Salt:            types.NewID(note.Salt),
		CommitmentIndex: proof.Index,
		InclusionProof: circparams.InclusionProof{
			Hashes: proof.Hashes,
			Flags:  proof.Flags,
		},
		Script:          selectScript(note.LockingScript.ScriptCommitment),
		LockingParams:   note.LockingScript.LockingParams,
		UnlockingParams: "",
	}

	state := new(types.State)
	if err := state.Deserialize(note.State); err != nil {
		return types.Nullifier{}, circparams.PrivateInput{}, err
	}
	privIn.State = *state

	nullifier, err := types.CalculateNullifier(proof.Index, privIn.Salt, note.LockingScript.ScriptCommitment, note.LockingScript.LockingParams...)
	if err != nil {
		return types.Nullifier{}, circparams.PrivateInput{}, err
	}
	return nullifier, privIn, nil
}

func buildOutput(addr Address, amt types.Amount, state types.State) (*transactions.Output, circparams.PrivateOutput, error) {
	addrScriptHash := addr.ScriptHash()
	salt, err := types.RandomSalt()
	if err != nil {
		return nil, circparams.PrivateOutput{}, err
	}
	outputNote := types.SpendNote{
		ScriptHash: addrScriptHash,
		Amount:     amt,
		AssetID:    types.IlliumCoinID,
		State:      state,
		Salt:       salt,
	}

	outputCommitment, err := outputNote.Commitment()
	if err != nil {
		return nil, circparams.PrivateOutput{}, err
	}

	serializedOutputNote, err := outputNote.Serialize()
	if err != nil {
		return nil, circparams.PrivateOutput{}, err
	}
	toViewKey, ok := addr.ViewKey().(*crypto.Curve25519PublicKey)
	if !ok {
		return nil, circparams.PrivateOutput{}, errors.New("address view key is not curve25519")
	}
	outputCipherText, err := toViewKey.Encrypt(serializedOutputNote)
	if err != nil {
		return nil, circparams.PrivateOutput{}, err
	}

	txOut := &transactions.Output{
		Commitment: outputCommitment[:],
		Ciphertext: outputCipherText,
	}

	privOut := circparams.PrivateOutput{
		ScriptHash: addrScriptHash,
		Amount:     amt,
		Salt:       outputNote.Salt,
		AssetID:    outputNote.AssetID,
		State:      outputNote.State,
	}

	return txOut, privOut, nil
}

func shuffleTransaction(raw *RawTransaction) {
	if raw.Tx.GetStandardTransaction() != nil {
		mrand.Shuffle(len(raw.Tx.GetStandardTransaction().Nullifiers), func(i, j int) {
			raw.Tx.GetStandardTransaction().Nullifiers[i], raw.Tx.GetStandardTransaction().Nullifiers[j] = raw.Tx.GetStandardTransaction().Nullifiers[j], raw.Tx.GetStandardTransaction().Nullifiers[i]
			raw.PrivateInputs[i], raw.PrivateInputs[j] = raw.PrivateInputs[j], raw.PrivateInputs[i]
		})
		mrand.Shuffle(len(raw.Tx.GetStandardTransaction().Outputs), func(i, j int) {
			raw.Tx.GetStandardTransaction().Outputs[i], raw.Tx.GetStandardTransaction().Outputs[j] = raw.Tx.GetStandardTransaction().Outputs[j], raw.Tx.GetStandardTransaction().Outputs[i]
			raw.PrivateOutputs[i], raw.PrivateOutputs[j] = raw.PrivateOutputs[j], raw.PrivateOutputs[i]
		})
	}
}

func selectScript(scriptCommitment []byte) string {
	if bytes.Equal(scriptCommitment, zk.BasicTransferScriptCommitment()) {
		return zk.BasicTransferScript()
	} else if bytes.Equal(scriptCommitment, zk.MultisigScriptCommitment()) {
		return zk.MultisigScript()
	} else if bytes.Equal(scriptCommitment, zk.TimelockedMultisigScriptCommitment()) {
		return zk.TimelockedMultisigScript()
	}
	return ""
}
