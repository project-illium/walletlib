// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"crypto/rand"
	"errors"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/transactions"
	"github.com/project-illium/ilxd/zk/circuits/standard"
	"github.com/project-illium/walletlib/pb"
	mrand "math/rand"
	"time"
)

const DefaultLocktimePrecision = 60 * 20

type RawTransaction struct {
	Tx             *transactions.Transaction
	PrivateInputs  []standard.PrivateInput
	PrivateOutputs []standard.PrivateOutput
}

// RawInput represents either a commitment or a private input
// Set one or the other fields but not both.
type RawInput struct {
	Commitment   []byte
	PrivateInput *standard.PrivateInput
}
type RawOutput struct {
	Addr   Address
	Amount types.Amount
	State  [128]byte
}

type InputSource func(amount types.Amount) (types.Amount, []*pb.SpendNote, error)
type ChangeSource func() (Address, error)
type ProofsSource func(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error)

func BuildTransaction(outputs []*RawOutput, fetchInputs InputSource, fetchChange ChangeSource, fetchProofs ProofsSource, feePerKB types.Amount) (*RawTransaction, error) {
	raw := &RawTransaction{
		Tx:             &transactions.Transaction{},
		PrivateInputs:  []standard.PrivateInput{},
		PrivateOutputs: []standard.PrivateOutput{},
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

		txOut, privOut, err := buildOutput(changeAddr, totalIn-(toAmt+fee), [128]byte{})
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
		PrivateInputs:  []standard.PrivateInput{},
		PrivateOutputs: []standard.PrivateOutput{},
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

	txOut, privOut, err := buildOutput(toAddr, totalIn-fee, [128]byte{})
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

func buildInput(note *pb.SpendNote, proof *blockchain.InclusionProof) (types.Nullifier, standard.PrivateInput, error) {
	privIn := standard.PrivateInput{
		Amount:          note.Amount,
		CommitmentIndex: proof.Index,
		InclusionProof: standard.InclusionProof{
			Hashes: proof.Hashes,
			Flags:  proof.Flags,
		},
		ScriptCommitment: note.UnlockingScript.ScriptCommitment,
		ScriptParams:     note.UnlockingScript.ScriptParams,
	}
	copy(privIn.Salt[:], note.Salt)
	copy(privIn.AssetID[:], note.Asset_ID)
	copy(privIn.State[:], note.State)

	nullifier := types.CalculateNullifier(proof.Index, privIn.Salt, privIn.ScriptCommitment, privIn.ScriptParams...)
	return nullifier, privIn, nil
}

func buildOutput(addr Address, amt types.Amount, state [128]byte) (*transactions.Output, standard.PrivateOutput, error) {
	addrScriptHash := addr.ScriptHash()
	var salt [32]byte
	rand.Read(salt[:])
	outputNote := types.SpendNote{
		ScriptHash: addrScriptHash[:],
		Amount:     amt,
		AssetID:    types.IlliumCoinID,
		State:      state,
		Salt:       salt,
	}

	outputCommitment := outputNote.Commitment()

	serializedOutputNote := outputNote.Serialize()
	toViewKey, ok := addr.ViewKey().(*crypto.Curve25519PublicKey)
	if !ok {
		return nil, standard.PrivateOutput{}, errors.New("address view key is not curve25519")
	}
	outputCipherText, err := toViewKey.Encrypt(serializedOutputNote)
	if err != nil {
		return nil, standard.PrivateOutput{}, err
	}

	txOut := &transactions.Output{
		Commitment: outputCommitment[:],
		Ciphertext: outputCipherText,
	}

	privOut := standard.PrivateOutput{
		ScriptHash: addrScriptHash[:],
		Amount:     uint64(amt),
		Salt:       outputNote.Salt,
		AssetID:    outputNote.AssetID,
		State:      outputNote.State,
	}

	return txOut, privOut, nil
}

func shuffleTransaction(raw *RawTransaction) {
	if raw.Tx.GetStandardTransaction() != nil {
		mrand.Seed(time.Now().Unix())
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
