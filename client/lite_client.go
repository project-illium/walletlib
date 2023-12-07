// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package client

import (
	"context"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/project-illium/ilxd/blockchain"
	icrypto "github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/repo"
	"github.com/project-illium/ilxd/rpc/pb"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
)

type LiteClient struct {
	blockchainClient pb.BlockchainServiceClient
	wsClient         pb.WalletServerServiceClient
	viewKeyBytes     []byte
	authToken        string
	ctx              context.Context
	done             context.CancelFunc
}

func NewLiteClient(serverAddr, rpcCertPath, authToken string) (*LiteClient, error) {
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

	return &LiteClient{
		blockchainClient: pb.NewBlockchainServiceClient(conn),
		wsClient:         pb.NewWalletServerServiceClient(conn),
		authToken:        authToken,
		ctx:              ctx,
		done:             done,
	}, nil
}

func (c *LiteClient) IsFullClient() bool {
	return false
}

func (c *LiteClient) Register(viewKey *icrypto.Curve25519PrivateKey, ul types.UnlockingScript, walletBirthday int64) error {
	keyBytes, err := crypto.MarshalPrivateKey(viewKey)
	if err != nil {
		return err
	}
	c.viewKeyBytes = keyBytes

	_, err = c.wsClient.RegisterViewKey(makeContext(c.ctx, c.authToken), &pb.RegisterViewKeyRequest{
		ViewKey:                   keyBytes,
		SerializedUnlockingScript: ul.Serialize(),
		Birthday:                  walletBirthday,
	})
	return err
}

func (c *LiteClient) Broadcast(tx *transactions.Transaction) error {
	_, err := c.blockchainClient.SubmitTransaction(makeContext(c.ctx, c.authToken), &pb.SubmitTransactionRequest{
		Transaction: tx,
	})
	return err
}

func (c *LiteClient) GetBlocks(from, to uint32) ([]*blocks.Block, uint32, error) {
	resp, err := c.wsClient.GetWalletTransactions(makeContext(c.ctx, c.authToken), &pb.GetWalletTransactionsRequest{
		ViewKey: c.viewKeyBytes,
		StartBlock: &pb.GetWalletTransactionsRequest_Height{
			Height: from,
		},
	})
	if err != nil {
		return nil, 0, err
	}
	blk := &blocks.Block{
		Header: &blocks.BlockHeader{
			Height: resp.ChainHeight,
		},
		Transactions: resp.Transactions,
	}

	return []*blocks.Block{blk}, resp.ChainHeight, nil
}

func (c *LiteClient) GetAccumulatorCheckpoint(height uint32) (*blockchain.Accumulator, uint32, error) {
	return nil, 0, ErrUnimplemented
}

func (c *LiteClient) SubscribeBlocks() (<-chan *blocks.Block, error) {
	ch := make(chan *blocks.Block)

	stream, err := c.wsClient.SubscribeTransactions(makeContext(c.ctx, c.authToken), &pb.SubscribeTransactionsRequest{
		ViewKeys: [][]byte{
			c.viewKeyBytes,
		},
	})
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

			ch <- &blocks.Block{
				Header:       &blocks.BlockHeader{},
				Transactions: []*transactions.Transaction{notif.Transaction},
			}
		}
	}()

	return ch, nil
}

func (c *LiteClient) GetInclusionProofs(commitments ...types.ID) ([]*blockchain.InclusionProof, types.ID, error) {
	cmts := make([][]byte, 0, len(commitments))
	for _, c := range commitments {
		cmts = append(cmts, c.Bytes())
	}
	resp, err := c.wsClient.GetTxoProof(makeContext(c.ctx, c.authToken), &pb.GetTxoProofRequest{
		Commitments: cmts,
	})
	if err != nil {
		return nil, types.ID{}, err
	}
	var (
		proofs = make([]*blockchain.InclusionProof, 0, len(resp.Proofs))
		root   types.ID
	)
	for _, p := range resp.Proofs {
		proofs = append(proofs, &blockchain.InclusionProof{
			ID:     types.NewID(p.Commitment),
			Hashes: p.Hashes,
			Flags:  p.Flags,
			Index:  p.Index,
		})
		root = types.NewID(p.TxoRoot)
	}
	return proofs, root, nil
}

func (c *LiteClient) Close() {
	c.done()
}
