// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"github.com/project-illium/ilxd/blockchain"
	icrypto "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
)

// BlockchainClient is an interfaced used by the wallet to fetch data about the blockchain.
// This can come from an internal library (see InternalClient) or an external node (see
// RPCClient or LiteClient).
type BlockchainClient interface {
	// IsFullClient returns whether this client is a full client (one that downloads and
	// scans all blocks) or a lite client (one that outsources block scanning to a
	// server).
	//
	// If True GetAccumulatorCheckpoint will be implemented and GetInclusionProofs and
	// Register will be unimplemented.
	//
	// If False GetInclusionProofs and Register will be implemented and GetAccumulatorCheckpoint
	//will be unimplemented.
	IsFullClient() bool

	// Register is used to register the client with a server.
	//
	// This should only be implemented if IsFullClient is false.
	Register(viewKey *icrypto.Curve25519PrivateKey, ul types.UnlockingScript, walletBirthday int64) error

	// Broadcast must broadcast the transaction to the illium network
	Broadcast(tx *transactions.Transaction) error

	// GetBlocks must return the blocks at the given height range or an error
	GetBlocks(from, to uint32) ([]*blocks.Block, error)

	// GetAccumulatorCheckpoint must return an accumulator checkpoint at the
	// nearest prior height along with the actual height of the checkpoint.
	//
	// // This should only be implemented if IsFullClient returns True.
	GetAccumulatorCheckpoint(height uint32) (*blockchain.Accumulator, uint32, error)

	// GetInclusionProofs returns the inclusion proofs for the given commitments.
	//
	// This should only be implemented if IsFullClient returns False.
	GetInclusionProofs(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error)

	// SubscribeBlocks must return a channel upon which new blocks are passed
	// when they are finalized.
	SubscribeBlocks() (<-chan *blocks.Block, error)

	// Close is called when the wallet is shutting down. It allows the client
	// to gracefully cleanup.
	Close()
}
