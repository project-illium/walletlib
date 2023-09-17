// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/project-illium/ilxd/blockchain"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/rpc/pb"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"io"
)

const authenticationTokenKey = "AuthenticationToken"

type RPCClient struct {
	client    pb.BlockchainServiceClient
	authToken string
	ctx       context.Context
	done      context.CancelFunc
}

func NewRPCClient(serverAddr, rpcCertPath, authToken string) (*RPCClient, error) {
	certFile := repo.CleanAndExpandPath(rpcCertPath)

	var (
		creds credentials.TransportCredentials
		err   error
	)
	if rpcCertPath != "" {
		creds, err = credentials.NewClientTLSFromFile(certFile, "")
		if err != nil {
			return nil, err
		}
	} else {
		creds = credentials.NewClientTLSFromCert(nil, "")
	}
	ma, err := multiaddr.NewMultiaddr(serverAddr)
	if err != nil {
		return nil, err
	}

	netAddr, err := manet.ToNetAddr(ma)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial(netAddr.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	ctx, done := context.WithCancel(context.Background())
	return &RPCClient{
		client:    pb.NewBlockchainServiceClient(conn),
		authToken: authToken,
		ctx:       ctx,
		done:      done,
	}, nil
}

func (c *RPCClient) Broadcast(tx *transactions.Transaction) error {
	_, err := c.client.SubmitTransaction(makeContext(c.ctx, c.authToken), &pb.SubmitTransactionRequest{
		Transaction: tx,
	})
	return err
}

func (c *RPCClient) GetBlocks(from, to uint32) ([]*blocks.Block, error) {
	resp, err := c.client.GetCompressedBlocks(makeContext(c.ctx, c.authToken), &pb.GetCompressedBlocksRequest{
		StartHeight: from,
		EndHeight:   to,
	})
	if err != nil {
		return nil, err
	}
	ret := make([]*blocks.Block, 0, len(resp.Blocks))
	for _, blk := range resp.Blocks {
		ret = append(ret, compressedBlockToBlock(blk))
	}
	return ret, nil
}

func (c *RPCClient) GetAccumulatorCheckpoint(height uint32) (*blockchain.Accumulator, uint32, error) {
	resp, err := c.client.GetAccumulatorCheckpoint(makeContext(c.ctx, c.authToken), &pb.GetAccumulatorCheckpointRequest{
		HeightOrTimestamp: &pb.GetAccumulatorCheckpointRequest_Height{Height: height},
	})
	if err != nil {
		return nil, 0, err
	}
	return blockchain.NewAccumulatorFromData(resp.Accumulator, resp.NumEntries), resp.Height, nil
}

func (c *RPCClient) SubscribeBlocks() (<-chan *blocks.Block, error) {
	ch := make(chan *blocks.Block)

	stream, err := c.client.SubscribeCompressedBlocks(makeContext(c.ctx, c.authToken), &pb.SubscribeCompressedBlocksRequest{})
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(ch)
		for {
			notif, err := stream.Recv()
			if err == io.EOF {
				return
			}

			ch <- compressedBlockToBlock(notif.Block)
		}
	}()

	return ch, nil
}

func (c *RPCClient) Close() {
	c.done()
}

func compressedBlockToBlock(compressed *blocks.CompressedBlock) *blocks.Block {
	blk := &blocks.Block{
		Header: &blocks.BlockHeader{
			Height: compressed.Height,
		},
		Transactions: make([]*transactions.Transaction, 0, len(compressed.Txs)),
	}
	for _, ctx := range compressed.Txs {
		tx := transactions.WrapTransaction(&transactions.StandardTransaction{
			Outputs:    ctx.Outputs,
			Nullifiers: ctx.Nullifiers,
		})
		tx.CacheTxid(types.NewID(ctx.Txid))
		blk.Transactions = append(blk.Transactions, tx)
	}
	return blk
}

func makeContext(ctx context.Context, authToken string) context.Context {
	if authToken != "" {
		md := metadata.Pairs(authenticationTokenKey, authToken)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	return ctx
}
