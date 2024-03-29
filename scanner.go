// Copyright (c) 2022 The illium developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package walletlib

import (
	"bytes"
	"github.com/project-illium/ilxd/crypto"
	"github.com/project-illium/ilxd/types"
	"github.com/project-illium/ilxd/types/blocks"
	"github.com/project-illium/ilxd/types/transactions"
	"golang.org/x/exp/slices"
	"runtime"
	"sync"
)

// ScanMatch represents an output that has decrypted with one of
// our scan keys.
type ScanMatch struct {
	Key           *crypto.Curve25519PrivateKey
	Commitment    types.ID
	DecryptedNote []byte
}

type scanWork struct {
	tx    *transactions.Transaction
	index int
}

// TransactionScanner is used to scan transaction outputs and attempt to decrypt
// each one. This allows us to flag outputs to be protected by the accumulator.
// One could perform this function outside the blockchain package and independently
// transaction the accumulator and inclusion proofs, but that would require double
// hashes of the accuumulator for every block.
type TransactionScanner struct {
	keys        []*crypto.Curve25519PrivateKey
	publicAddrs map[types.ID]*crypto.Curve25519PrivateKey
	mtx         sync.RWMutex
}

// NewTransactionScanner returns a new TransactionScanner
func NewTransactionScanner(keys ...*crypto.Curve25519PrivateKey) *TransactionScanner {
	return &TransactionScanner{
		keys:        keys,
		publicAddrs: make(map[types.ID]*crypto.Curve25519PrivateKey),
		mtx:         sync.RWMutex{},
	}
}

// NewTransactionScannerWithPublicAddrs returns a new TransactionScanner initialized
// with both view keys and public address scriptHashes.
func NewTransactionScannerWithPublicAddrs(keyMap map[types.ID]*crypto.Curve25519PrivateKey) *TransactionScanner {
	keys := make([]*crypto.Curve25519PrivateKey, 0, len(keyMap))
	for _, key := range keyMap {
		keys = append(keys, key)
	}
	return &TransactionScanner{
		keys:        keys,
		publicAddrs: keyMap,
		mtx:         sync.RWMutex{},
	}
}

// AddKeys adds new scan keys to the TransactionScanner
func (s *TransactionScanner) AddKeys(keys ...*crypto.Curve25519PrivateKey) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

keyLoop:
	for _, k := range keys {
		for _, key := range s.keys {
			if k.Equals(key) {
				continue keyLoop
			}
		}
		s.keys = append(s.keys, k)
	}
}

// AddScriptHash adds new public address script hashes to the scanner.
func (s *TransactionScanner) AddScriptHash(scriptHash types.ID, key *crypto.Curve25519PrivateKey) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.publicAddrs[scriptHash] = key
}

// RemoveKey removes scan keys from the TransactionScanner
func (s *TransactionScanner) RemoveKey(key *crypto.Curve25519PrivateKey) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for i, k := range s.keys {
		if k.Equals(key) {
			s.keys = slices.Delete(s.keys, i, i+1)
		}
	}
}

// ScanOutputs attempts to decrypt the outputs using the keys and returns a map of matches
func (s *TransactionScanner) ScanOutputs(blk *blocks.Block) map[types.ID]*ScanMatch {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	ret := make(map[types.ID]*ScanMatch)
	if len(s.keys) == 0 {
		return ret
	}

	maxGoRoutines := runtime.NumCPU() * 3
	if maxGoRoutines <= 0 {
		maxGoRoutines = 1
	}
	outputs := len(blk.Outputs())
	if maxGoRoutines > outputs {
		maxGoRoutines = outputs
	}

	done := make(chan struct{})
	workChan := make(chan *scanWork)
	resultChan := make(chan *ScanMatch)

	for i := 0; i < maxGoRoutines; i++ {
		go s.scanHandler(workChan, resultChan, done)
	}

	defer close(done)
	defer close(resultChan)

	go func() {
		for _, tx := range blk.Transactions {
			for i := range tx.Outputs() {
				workChan <- &scanWork{
					tx:    tx,
					index: i,
				}
			}
		}
		close(workChan)
	}()

	for i := 0; i < outputs; i++ {
		match := <-resultChan
		if match != nil {
			ret[match.Commitment] = match
		}
	}
	return ret
}

func (s *TransactionScanner) scanHandler(workChan chan *scanWork, resultChan chan *ScanMatch, done chan struct{}) {
workloop:
	for {
		select {
		case w := <-workChan:
			if w != nil {
				output := w.tx.Outputs()[w.index]
				if len(output.Ciphertext) >= 160 && bytes.Equal(output.Ciphertext[0:32], publicAddrScriptHash) {
					for sh, k := range s.publicAddrs {
						if bytes.Equal(output.Ciphertext[128:160], sh.Bytes()) {
							resultChan <- &ScanMatch{
								Key:           k,
								Commitment:    types.NewID(output.Commitment),
								DecryptedNote: output.Ciphertext,
							}
							continue workloop
						}
					}
				}
				for _, k := range s.keys {
					decrypted, err := k.Decrypt(output.Ciphertext)
					if err == nil {
						resultChan <- &ScanMatch{
							Key:           k,
							Commitment:    types.NewID(output.Commitment),
							DecryptedNote: decrypted,
						}
						continue workloop
					}
				}
				resultChan <- nil
			}
		case <-done:
			return
		}
	}
}
