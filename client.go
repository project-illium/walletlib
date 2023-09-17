// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
)

// BlockchainClient is an interfaced used by the wallet to fetch data about the blockchain.
// This can come from an internal library (see InternalClient) or an external node (see
// RPCClient).
type BlockchainClient interface {
	// Broadcast must broadcast the transaction to the illium network
	Broadcast(tx *transactions.Transaction) error

	// GetBlock must return the block at the given height or an error
	GetBlock(height uint32) (*blocks.Block, error)

	// GetAccumulatorCheckpoint must return an accumulator checkpoint at the
	// nearest prior height along with the actual height of the checkpoint.
	GetAccumulatorCheckpoint(height uint32) (*blockchain.Accumulator, uint32, error)

	// SubscribeBlocks must return a channel upon which new blocks are passed
	// when they are finalized.
	SubscribeBlocks() (<-chan *blocks.Block, error)

	// Close is called when the wallet is shutting down. It allows the client
	// to gracefully cleanup.
	Close()
}
