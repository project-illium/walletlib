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

// InternalClient is a convenience class that makes it easy for an internal library
// to satisfy the BlockchainClient interface.
type InternalClient struct {
	BroadcastFunc                func(tx *transactions.Transaction) error
	GetBlockFunc                 func(height uint32) (*blocks.Block, error)
	GetAccumulatorCheckpointFunc func(height uint32) (*blockchain.Accumulator, uint32, error)
	SubscribeBlocksFunc          func() (<-chan *blocks.Block, error)
	CloseFunc                    func()
}

func (c *InternalClient) Broadcast(tx *transactions.Transaction) error {
	return c.BroadcastFunc(tx)
}

func (c *InternalClient) GetBlock(height uint32) (*blocks.Block, error) {
	return c.GetBlockFunc(height)
}

func (c *InternalClient) GetAccumulatorCheckpoint(height uint32) (*blockchain.Accumulator, uint32, error) {
	return c.GetAccumulatorCheckpointFunc(height)
}

func (c *InternalClient) SubscribeBlocks() (<-chan *blocks.Block, error) {
	return c.SubscribeBlocksFunc()
}

func (c *InternalClient) Close() {
	c.CloseFunc()
}
