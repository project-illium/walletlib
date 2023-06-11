// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/params/hash"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/zk"
)

// IsDustInput returns true if the additional fee needed to attach
// the input onto a larger transaction would exceed the value of the
// input.
//
// Note that this only considers the marginal cost of an additional
// input. It does not consider the cost of spending this input by
// itself which would be substantially higher due to the proof size.
func IsDustInput(amount, feePerKB types.Amount) bool {
	feePerNullifier := (float64(feePerKB) / 1000) * float64(types.NullifierSize)
	return float64(amount) <= feePerNullifier
}

// ComputeFee returns the fee for the estimated size of the transaction.
func ComputeFee(inputs, outputs int, feePerKB types.Amount) types.Amount {
	size := EstimateSerializedSize(inputs, outputs, true)
	sizeInKB := float64(size) / 1000
	return types.Amount(float64(feePerKB) * sizeInKB)
}

// EstimateSerializedSize returns the estimated size of the transaction.
func EstimateSerializedSize(inputs, outputs int, addChangeOutput bool) types.Amount {
	// Estimated base protobuf size:
	// base +40 (a buffer to make sure we don't under-estimate)
	// output +1
	// nullifier +2
	// fee +2
	baseSize := 40 + 1 + 2 + 2
	txoRootSize := hash.HashSize + 4
	nullifierSize := types.NullifierSize + 2
	outputSize := types.CommitmentLen + blockchain.CiphertextLen + 8

	if addChangeOutput {
		outputs += 1
	}

	return types.Amount(baseSize + txoRootSize + (nullifierSize * inputs) + (outputSize * outputs) + zk.MockProofSize)
}
